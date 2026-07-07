// Command demo-backend runs the ATI demo weather agent (Agent B) as a
// standalone process. The agent logic lives in internal/demo/backend.
package main

import (
	"flag"
	"log"
	"os"

	"gitlab.alibaba-inc.com/alibaba-dns/ati-golang-sdk/internal/demo/backend"
)

func main() {
	listenAddr := flag.String("listen", ":7100", "listen address")
	dashKeyFlag := flag.String("dashscope-key", "", "DashScope API key (or set DASHSCOPE_API_KEY env)")
	dashModelFlag := flag.String("dashscope-model", "", "DashScope model (or set DASHSCOPE_MODEL_NAME env, default qwen-plus)")
	flag.Parse()

	dashKey := *dashKeyFlag
	if dashKey == "" {
		dashKey = os.Getenv("DASHSCOPE_API_KEY")
	}
	dashModel := *dashModelFlag
	if dashModel == "" {
		dashModel = os.Getenv("DASHSCOPE_MODEL_NAME")
	}

	if err := backend.Run(backend.Config{
		ListenAddr: *listenAddr,
		DashKey:    dashKey,
		DashModel:  dashModel,
	}); err != nil {
		log.Fatal(err)
	}
}
