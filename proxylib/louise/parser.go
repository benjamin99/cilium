package louise

import (
	"bytes"
	. "github.com/cilium/cilium/proxylib/proxylib"
	cilium "github.com/cilium/proxy/go/cilium/api"
	log "github.com/sirupsen/logrus"
)

const (
	parserName = "louise"
)

func init() {
	log.Debug("init(): Registering luise factories")
	RegisterL7RuleParser("dcard.louise", ruleParser)
	RegisterParserFactory("dcard.louise", &LouiseParserFactory{})
}

/** Rule Parser */

type louise struct {}

func (r *louise) Matches(data interface{}) bool {
	return true
}

func ruleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	rules := rule.GetL7Rules()
	if rules == nil {
		return nil
	}
	allowRules := rules.GetL7AllowRules()
	parsed := make([]L7NetworkPolicyRule, 0, len(allowRules))
	for range allowRules {
		parsed = append(parsed, &louise{})
	}
	return parsed
}

/** Parser Factory */

type LouiseParserFactory struct {}

func (f *LouiseParserFactory) Create(connection *Connection) interface{} {
	return &LouiseParser{connection: connection}
}

/** Parser */

type LouiseParser struct {
	connection *Connection
}

func (p *LouiseParser) OnData(reply, endStream bool, dataArray [][]byte) (op OpType, N int) {
	data := string(bytes.Join(dataArray, []byte{}))
	log.Debugf("OnData: %s", data)

	

}

