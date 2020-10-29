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
	"context"
	"fmt"
	"regexp"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/libbeat/outputs"
	"github.com/elastic/beats/v7/libbeat/publisher"
)

var (
	name = "ding_robot"
)

type dingRobot struct {
	beat       beat.Info
	observer   outputs.Observer
	config     config
	log        *logp.Logger
	groupRules map[string]*groupRule
	matchRules map[*regexp.Regexp]*groupRule
}

func init() {
	outputs.RegisterType(name, makeDingRobot)
}

func makeDingRobot(
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
	dingRobotFactory, err := newDingRobot(beat, observer, defaultConfig)
	if err != nil {
		return outputs.Fail(fmt.Errorf("%s output initialization failed with: %v", name, err))
	}
	dingRobotFactory.Start()
	return outputs.Success(-1, 0, dingRobotFactory)
}

func newDingRobot(beat beat.Info, observer outputs.Observer, cfg config) (*dingRobot, error) {
	log := logp.NewLogger(name)
	groupRules, err := cfg.makeGroupRules(beat.Hostname, log)
	if err != nil {
		return nil, err
	}
	matchRules, err := cfg.makeMatchRules(groupRules)
	if err != nil {
		return nil, err
	}
	dingRobotFactory := &dingRobot{
		beat:       beat,
		observer:   observer,
		config:     cfg,
		log:        log,
		groupRules: groupRules,
		matchRules: matchRules,
	}
	return dingRobotFactory, nil
}

func (r *dingRobot) Start() error {
	for _, rule := range r.groupRules {
		go rule.start()
	}
	return nil
}

func (r *dingRobot) Close() error {
	for _, rule := range r.groupRules {
		go rule.close()
	}
	return nil
}

func (r *dingRobot) handleEvents(events []publisher.Event) ([]publisher.Event, int, error) {
	var failed []publisher.Event
	var dropped int
	for _, event := range events {
		message, err := event.Content.Fields.GetValue("message")
		if err != nil {
			dropped++
			r.log.Errorf("get message field failed, %s", err)
			continue
		}
		messageStr, converted := message.(string)
		if !converted {
			dropped++
			r.log.Errorf("message field is not string")
			continue
		}
		for match, rule := range r.matchRules {
			if match.MatchString(messageStr) {
				go rule.push(messageStr)
			}
		}
	}
	return failed, dropped, nil
}

func (r *dingRobot) Publish(_ context.Context, batch publisher.Batch) error {
	observer := r.observer
	events := batch.Events()
	observer.NewBatch(len(events))
	failed, dropped, err := r.handleEvents(events)
	observer.Dropped(dropped)
	observer.Failed(len(failed))
	observer.Acked(len(events) - len(failed) - dropped)
	if len(failed) != 0 {
		batch.RetryEvents(failed)
	} else {
		batch.ACK()
	}
	return err
}

func (r *dingRobot) String() string {
	return name
}
