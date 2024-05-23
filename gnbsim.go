// SPDX-FileCopyrightText: 2022 Great Software Laboratory Pvt. Ltd
// SPDX-FileCopyrightText: 2021 Open Networking Foundation <info@opennetworking.org>
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/omec-project/gnbsim/common"
	"github.com/omec-project/gnbsim/factory"
	"github.com/omec-project/gnbsim/gnodeb"
	"github.com/omec-project/gnbsim/httpserver"
	"github.com/omec-project/gnbsim/logger"
	prof "github.com/omec-project/gnbsim/profile"
	profctx "github.com/omec-project/gnbsim/profile/context"
	"github.com/omec-project/gnbsim/stats"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "GNBSIM"
	app.Usage = "./gnbsim"
	app.Action = action

	logger.AppLog.Infoln("App Name:", app.Name)

	if err := app.Run(os.Args); err != nil {
		logger.AppLog.Errorln("Failed to run GNBSIM:", err)
		return
	}
}

func action(c *cli.Context) error {

	// load the configuration
	cfg := c.String("test.config")
	if err := factory.InitConfigFactory(cfg); err != nil {
		logger.AppLog.Errorln("Failed to initialize config factory:", err)
		return err
	}

	config := factory.AppConfig

	// Initiating a server for profiling
	logger.SetLogLevel("Debug")

	// TODO: pass in the config sections for gnodeb
	err := gnodeb.InitializeAllGnbs()
	if err != nil {
		logger.AppLog.Errorln("Failed to initialize gNodeBs:", err)
		return err
	}

	// Keep this because we want to make sure we pass?
	go ListenAndLogSummary()

	var appWaitGrp sync.WaitGroup
	if config.Configuration.Server.Enable {
		appWaitGrp.Add(1)
		go func() {
			defer appWaitGrp.Done()
			err := httpserver.StartHttpServer()
			if err != nil {
				logger.AppLog.Infoln("StartHttpServer returned :", err)
			}
		}()

		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-signalChannel
			logger.AppLog.Infoln("StopHttpServer called")
			httpserver.StopHttpServer()
			logger.AppLog.Infoln("StopHttpServer returned ")
		}()
	}

	// This configuration enables running the configured profiles
	// when gnbsim is started. It is enabled by default. If we want no
	// profiles to run and gnbsim to wait for a command, then we
	// should disable this config.
	if config.Configuration.RunConfigProfilesAtStart {
		var profileWaitGrp sync.WaitGroup
		// start profile and wait for it to finish (success or failure)
		// Keep running gnbsim as long as profiles are not finished
		for _, profile := range config.Configuration.Profiles {
			if !profile.Enable {
				logger.AppLog.Errorln("disabled profileType ", profile.ProfileType)
				continue
			}
			profileWaitGrp.Add(1)

			prof.InitProfile(profile, profctx.SummaryChan)

			go func(profileCtx *profctx.Profile) {
				defer profileWaitGrp.Done()
				prof.ExecuteProfile(profileCtx, profctx.SummaryChan)
			}(profile)

			if !config.Configuration.ExecInParallel {
				profileWaitGrp.Wait()
			}
		}

		if config.Configuration.ExecInParallel {
			profileWaitGrp.Wait()
		}
	}

	appWaitGrp.Wait()

	// should be good enough to send pending packets out of socket and process events on channel
	time.Sleep(time.Second * 5)
	stats.DumpStats()
	// TODO: To be removed. Allowing summary logger to dump the logs
	time.Sleep(time.Second * 5)

	return nil
}

// TODO : we don't keep track of how many profiles are started...
func ListenAndLogSummary() {
	for intfcMsg := range profctx.SummaryChan {
		// TODO: do we need this event ?
		if intfcMsg.GetEventType() == common.QUIT_EVENT {
			return
		}

		result := "PASS"
		// Waiting for execution summary from profile routine
		msg, ok := intfcMsg.(*common.SummaryMessage)
		if !ok {
			logger.AppLog.Fatalln("Invalid Message Type")
		}

		logger.AppSummaryLog.Infoln("Profile Name:", msg.ProfileName, ", Profile Type:", msg.ProfileType)
		logger.AppSummaryLog.Infoln("Ue's Passed:", msg.UePassedCount, ", Ue's Failed:", msg.UeFailedCount)

		if len(msg.ErrorList) != 0 {
			result = "FAIL"
			logger.AppSummaryLog.Infoln("Profile Errors:")
			for _, err := range msg.ErrorList {
				logger.AppSummaryLog.Errorln(err)
			}
		}
		logger.AppSummaryLog.Infoln("Profile Status:", result)
	}
}
