// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package dingrobot

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/publisher"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"text/template"
	"time"

	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/outputs/codec"
)

var (
	httpClient    = http.Client{Timeout: time.Second * 10}
	defaultConfig = config{}
)

type credentialConfig struct {
	Token  string `json:"token"`
	Secret string `json:"secret"`
}

type groupConfig struct {
	Name            string             `config:"name"`
	MaxMessageSleep time.Duration      `config:"max_message_sleep"`
	MaxMessageLines int32              `config:"max_message_lines"`
	Template        string             `config:"template"`
	Credentials     []credentialConfig `config:"credentials"`
}

type ruleConfig struct {
	Kind   string `config:"kind"`
	Regexp string `config:"regexp"`
	Group  string `config:"group"`
}

type config struct {
	Codec  codec.Config  `config:"codec"`
	Groups []groupConfig `config:"groups"`
	Rules  []ruleConfig  `config:"rules"`
}

func (c config) makeGroupRules(beat beat.Info, log *logp.Logger) (map[string]*groupRule, error) {
	groups := make(map[string]*groupRule)
	for _, group := range c.Groups {
		tpl, err := template.New(group.Name).Parse(group.Template)
		if err != nil {
			return nil, err
		}
		groups[group.Name] = &groupRule{
			status:          groupRuleStatusOpen,
			beat:            beat,
			log:             log,
			template:        tpl,
			credentials:     group.Credentials,
			credentialIndex: 0,
			maxMessageSleep: group.MaxMessageSleep,
			maxMessageLines: group.MaxMessageLines,
			messageChan:     make(chan publisher.Event, group.MaxMessageLines),
		}
	}
	return groups, nil
}

func (c config) makeMatchRules(groupRules map[string]*groupRule) (map[*regexp.Regexp]*groupRule, error) {
	matchRules := make(map[*regexp.Regexp]*groupRule)
	for _, rule := range c.Rules {
		groupRule, exist := groupRules[rule.Group]
		if !exist {
			return nil, fmt.Errorf("group %s not exist", rule.Group)
		}
		groupRule.setKind(rule.Kind)
		matchRules[regexp.MustCompile(rule.Regexp)] = groupRule
	}
	return matchRules, nil
}

const (
	groupRuleStatusClose = iota
	groupRuleStatusSleep
	groupRuleStatusOpen
)

type groupRule struct {
	m               sync.RWMutex
	status          int32 // 0 close 1 sleep
	beat            beat.Info
	log             *logp.Logger
	template        *template.Template
	credentials     []credentialConfig
	credentialIndex int
	kind            string
	maxMessageLines int32
	maxMessageSleep time.Duration
	messageChan     chan publisher.Event
}

func (g *groupRule) setKind(kind string) {
	g.kind = kind
}

func (g *groupRule) setStatus(status int32) {
	g.status = status
}

func (g *groupRule) resetMsgChan() {
	close(g.messageChan)
	g.messageChan = make(chan publisher.Event, g.maxMessageLines)
}

func (g *groupRule) credential() credentialConfig {
	g.credentialIndex = (g.credentialIndex + 1) % len(g.credentials)
	return g.credentials[g.credentialIndex]
}

func (g *groupRule) close() {
	g.m.Lock()
	defer g.m.Unlock()
	if g.status != groupRuleStatusClose {
		g.setStatus(groupRuleStatusClose)
		close(g.messageChan)
	}
}

func (g *groupRule) push(event publisher.Event) {
	g.m.RLock()
	status := g.status
	g.m.RUnlock()
	switch status {
	case groupRuleStatusClose:
		g.log.Error("group rule closed")
		return
	case groupRuleStatusSleep:
		g.log.Debug("group rule closed sleep")
		return
	case groupRuleStatusOpen:
		select {
		case g.messageChan <- event:
			g.log.Debug("push group message success")
		default:
			g.m.Lock()
			// 数据阻塞，处理不过来，规则开始休眠，n秒钟后打开该规则
			g.setStatus(groupRuleStatusSleep)
			g.resetMsgChan()
			time.AfterFunc(g.maxMessageSleep, func() {
				g.m.Lock()
				defer g.m.Unlock()
				g.setStatus(groupRuleStatusOpen)
			})
			credential := g.credential()
			g.m.Unlock()
			g.asyncSendDingRobotMessage(credential.Token, credential.Secret, fmt.Sprintf("%s:错误消息太多，请关注错误日志", g.beat.Name))
		}
	}
}

func (g *groupRule) start() {
	tk := time.NewTicker(time.Second * 3)
	defer tk.Stop()
	for {
		g.m.RLock()
		status := g.status
		g.m.RUnlock()
		if status == groupRuleStatusClose {
			return
		}
		<-tk.C
		go g.handleMessage()
	}
}

func (g *groupRule) handleMessage() {
	length := len(g.messageChan)
	if length <= 0 {
		g.log.Debug("read no message, looping")
		return
	}
	messages := make([]publisher.Event, length)
	for i := 0; i < length; i++ {
		messages[i] = <-g.messageChan
	}
	g.prepareMessage(messages...)
}

func (g *groupRule) prepareMessage(events ...publisher.Event) {
	length := len(events)
	if length <= 0 {
		return
	}
	data := make([]map[string]interface{}, length)
	for i, event := range events {
		message, err := event.Content.GetValue("message")
		if err != nil {
			g.log.Errorf("prepare message get message field failed, %s", err)
			continue
		}
		messageStr, converted := message.(string)
		if !converted {
			g.log.Errorf("prepare message message field is not string")
			continue
		}
		switch g.kind {
		case "json":
			var alert map[string]interface{}
			err := json.Unmarshal([]byte(messageStr), &alert)
			if err != nil {
				g.log.Errorf("unmarshal message error: %s", err)
				continue
			}
			alert["raw"] = message
			data[i] = alert
		default:
			data[i] = map[string]interface{}{
				"raw": message,
			}
		}
	}
	templateCache := bytes.NewBuffer(nil)
	err := g.template.Execute(templateCache, data)
	if err != nil {
		g.log.Errorf("execute template error: %s", err)
		return
	}
	g.m.Lock()
	credential := g.credential()
	g.m.Unlock()
	g.asyncSendDingRobotMessage(credential.Token, credential.Secret, templateCache.String())
}

func (g *groupRule) asyncSendDingRobotMessage(token, secret, message string) {
	go func() {
		err := g.sendDingRobotMessage(token, secret, message)
		if err != nil {
			g.log.Errorf("send ding robot message error: %s", err)
		}
	}()
}

func (g *groupRule) sendDingRobotMessage(token, secret, message string) error {
	if message == "" {
		return nil
	}
	body := bytes.NewBuffer([]byte{})
	err := json.NewEncoder(body).Encode(map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]interface{}{
			"title": "something error",
			"text":  message,
		},
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, "https://oapi.dingtalk.com/robot/send", body)
	if err != nil {
		return err
	}
	timestamp := time.Now().UnixNano() / 1e6
	query := make(url.Values)
	query.Set("access_token", token)
	query.Set("timestamp", fmt.Sprintf("%d", timestamp))
	str := fmt.Sprintf("%d\n%s", timestamp, secret)
	hash := hmac.New(sha256.New, []byte(secret))
	_, _ = hash.Write([]byte(str))
	sign := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	query.Set("sign", sign)
	request.URL.RawQuery = query.Encode()
	request.Header.Add("Content-Type", "application/json;charset=utf-8")
	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf(http.StatusText(response.StatusCode))
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	err = json.NewDecoder(response.Body).Decode(&result)
	if err != nil {
		return err
	}
	if result.ErrCode != 0 {
		return fmt.Errorf("code: %d, message: %s", result.ErrCode, result.ErrMsg)
	}
	return nil
}
