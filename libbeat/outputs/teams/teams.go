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

package teams

import (
	"context"
	"fmt"
	"regexp"
	"text/template"

	"github.com/Masterminds/sprig"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/publisher"
)

var (
	name = "teams"
)

type teams struct {
	beat       beat.Info
	observer   outputs.Observer
	config     config
	log        *logp.Logger
	rules      map[string]*robotRule
	matchRules map[*regexp.Regexp]*robotRule
}

func init() {
	outputs.RegisterType(name, makeTeams)
}

func makeTeams(
	_ outputs.IndexManager,
	beat beat.Info,
	observer outputs.Observer,
	cfg *common.Config,
) (outputs.Group, error) {
	err := cfg.Unpack(&defaultConfig)
	if err != nil {
		return outputs.Fail(err)
	}
	// disable bulk support in publisher pipeline
	cfg.SetInt("bulk_max_size", -1, -1)
	// new ding robot
	tm, err := newTeams(beat, observer, defaultConfig)
	if err != nil {
		return outputs.Fail(fmt.Errorf("%s output initialization failed with: %v", name, err))
	}
	tm.Start()
	return outputs.Success(-1, 0, tm)
}

func newTeams(beat beat.Info, observer outputs.Observer, cfg config) (*teams, error) {
	robot := &teams{
		beat:       beat,
		observer:   observer,
		config:     cfg,
		log:        logp.NewLogger(name),
		rules:      make(map[string]*robotRule),
		matchRules: make(map[*regexp.Regexp]*robotRule),
	}
	for _, g := range cfg.Groups {
		tpl, err := template.New(g.Name).Funcs(sprig.TxtFuncMap()).Parse(g.Template)
		if err != nil {
			return nil, err
		}
		cs := make([]*credential, len(g.Credentials))
		for i, c := range g.Credentials {
			cs[i] = &credential{
				enabled: true,
				url:     c,
			}
		}
		robot.rules[g.Name] = &robotRule{
			status:          ruleStatusOpen,
			beat:            beat,
			log:             robot.log,
			template:        tpl,
			credentials:     cs,
			credentialIndex: 0,
			messageChan:     make(chan publisher.Event, 20*10*len(cs)),
		}
	}
	for _, r := range cfg.Rules {
		rule, exist := robot.rules[r.Group]
		if !exist {
			return nil, fmt.Errorf("group %s not exist", r.Group)
		}
		rule.kind = r.Kind
		robot.matchRules[regexp.MustCompile(r.Regexp)] = rule
	}
	return robot, nil
}

func (t *teams) Start() error {
	for _, r := range t.rules {
		go r.Start()
	}
	return nil
}

func (t *teams) Close() error {
	for _, r := range t.rules {
		go r.Close()
	}
	return nil
}

func (t *teams) handleEvents(events []publisher.Event) ([]publisher.Event, int, error) {
	var failed []publisher.Event
	var dropped int
	for _, e := range events {
		message, err := e.Content.Fields.GetValue("message")
		if err != nil {
			dropped++
			t.log.Errorf("handle events get message field failed, %s", err)
			continue
		}
		messageStr, converted := message.(string)
		if !converted {
			dropped++
			t.log.Errorf("handle events message field is not string")
			continue
		}
		for m, r := range t.matchRules {
			if m.MatchString(messageStr) {
				go r.Push(e)
			}
		}
	}
	return failed, dropped, nil
}

func (t *teams) Publish(_ context.Context, batch publisher.Batch) error {
	ob := t.observer
	events := batch.Events()
	ob.NewBatch(len(events))
	failed, dropped, err := t.handleEvents(events)
	ob.Dropped(dropped)
	ob.Failed(len(failed))
	ob.Acked(len(events) - len(failed) - dropped)
	if len(failed) != 0 {
		batch.RetryEvents(failed)
	} else {
		batch.ACK()
	}
	return err
}

func (t *teams) String() string {
	return name
}
