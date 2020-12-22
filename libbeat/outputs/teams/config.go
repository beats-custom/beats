package teams

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"text/template"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/outputs/codec"
	"github.com/elastic/beats/v7/libbeat/publisher"
)

var (
	httpClient    = http.Client{Timeout: time.Second * 10}
	defaultConfig = config{}
)

type config struct {
	Codec  codec.Config `config:"codec"`
	Groups []struct {
		Name        string   `config:"name"`
		Template    string   `config:"template"`
		Credentials []string `config:"credentials"`
	} `config:"groups"`
	Rules []struct {
		Kind   string `config:"kind"`
		Regexp string `config:"regexp"`
		Group  string `config:"group"`
	} `config:"rules"`
}

const (
	ruleStatusClose = iota
	ruleStatusSleep
	ruleStatusOpen
)

type credential struct {
	enabled bool
	url     string
}

type robotRule struct {
	m               sync.RWMutex
	status          int32
	beat            beat.Info
	log             *logp.Logger
	template        *template.Template
	credentials     []*credential
	credentialIndex int
	kind            string
	messageChan     chan publisher.Event
}

func (r *robotRule) getCredential() *credential {
	r.credentialIndex = (r.credentialIndex + 1) % len(r.credentials)
	c := r.credentials[r.credentialIndex]
	if c.enabled == false {
		return nil
	}
	return c
}

func (r *robotRule) convertToSleep() {
	r.log.Error("retry send teams max times")
	r.m.Lock()
	r.status = ruleStatusSleep
	r.m.Unlock()
	time.AfterFunc(time.Minute, func() {
		r.m.Lock()
		r.status = ruleStatusOpen
		r.m.Unlock()
	})
}

func (r *robotRule) Close() error {
	r.m.Lock()
	defer r.m.Unlock()
	if r.status != ruleStatusClose {
		r.status = ruleStatusClose
		close(r.messageChan)
		return nil
	} else {
		return fmt.Errorf("robot rule closed")
	}
}

func (r *robotRule) Push(event publisher.Event) {
	r.m.RLock()
	status := r.status
	r.m.RUnlock()
	switch status {
	case ruleStatusClose:
		r.log.Error("rule closed")
		return
	case ruleStatusSleep:
		r.log.Debug("rule sleep")
		return
	case ruleStatusOpen:
		select {
		case r.messageChan <- event:
			r.log.Debug("push message success")
		default:
			r.convertToSleep()
		}
	}
}

func (r *robotRule) Start() {
	timer := time.NewTimer(time.Second * 3)
	for {
		r.m.RLock()
		status := r.status
		r.m.RUnlock()
		if status == ruleStatusClose {
			return
		}
		r.handleMessage(timer)
	}
}

func (r *robotRule) handleMessage(timer *time.Timer) {
	timer.Reset(time.Second * 3)
	defer timer.Stop()
	events := make([]publisher.Event, 0, 10)
	for i := 0; i < 10; i++ {
		select {
		case event, ok := <-r.messageChan:
			if ok {
				events = append(events, event)
			}
		case <-timer.C:
			goto TimeOver
		}
	}
TimeOver:
	go r.prepareMessage(events...)
}

func (r *robotRule) prepareMessage(events ...publisher.Event) {
	length := len(events)
	if length <= 0 {
		return
	}
	data := make([]common.MapStr, length)
	for i, event := range events {
		message, err := event.Content.GetValue("message")
		if err != nil {
			r.log.Errorf("get message field failed, %s", err)
			continue
		}
		file, err := event.Content.GetValue("log.file.path")
		if err != nil {
			r.log.Errorf("get log.file.path field failed, %s", err)
			continue
		}
		field := common.MapStr{}
		if r.kind == "json" {
			messageStr, converted := message.(string)
			if !converted {
				r.log.Error("message field is not string")
				continue
			}
			messageField := common.MapStr{}
			err = json.Unmarshal([]byte(messageStr), &messageField)
			if err != nil {
				r.log.Errorf("unmarshal message error: %s", err)
				continue
			}
			field.Update(messageField)
		}
		field.Put("raw", message)
		field.Put("file", file)
		field.Put("beatName", r.beat.Name)
		data[i] = field
	}
	templateCache := bytes.NewBuffer(nil)
	err := r.template.Execute(templateCache, data)
	if err != nil {
		r.log.Errorf("execute template error: %s", err)
		return
	}
	r.asyncSendTeamsMessage(templateCache.String())
}

func (r *robotRule) asyncSendTeamsMessage(message string) {
	go func() {
		retry := 1
	Retry:
		r.m.Lock()
		c := r.getCredential()
		r.m.Unlock()
		if c == nil {
			if retry <= len(r.credentials) {
				retry++
				r.log.Warnf("send message failed, retry: %d", retry)
				goto Retry
			} else {
				r.log.Error("retry send teams max times")
				r.convertToSleep()
				return
			}
		}
		err := r.sendTeamsMessage(c.url, message)
		if err != nil {
			r.log.Errorf("send message error: %s, retrying", err)
			r.m.Lock()
			c.enabled = false
			r.m.Unlock()
			time.AfterFunc(time.Minute, func() {
				r.m.Lock()
				c.enabled = true
				r.m.Unlock()
			})
			retry++
			goto Retry
		}
	}()
}

func (r *robotRule) sendTeamsMessage(url, message string) error {
	if message == "" {
		return nil
	}
	body := bytes.NewBuffer(nil)
	err := json.NewEncoder(body).Encode(map[string]string{
		"text": message,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json;charset=utf-8")
	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("code: %d, message: %s, data: %s", response.StatusCode, response.Status, string(data))
	}
	if string(data) != "1" {
		return fmt.Errorf("error response is %s", string(data))
	}
	return nil
}
