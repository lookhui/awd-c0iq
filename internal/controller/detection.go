package controller

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"awd-h1m-pro/internal/core/logic"
	"awd-h1m-pro/internal/util"
)

type DetectionController struct {
	service *logic.DetectionService
}

func NewDetectionController(service *logic.DetectionService) *DetectionController {
	return &DetectionController{service: service}
}

func (c *DetectionController) DetectHosts(targetsInput string) (map[string]any, error) {
	targets, err := c.parseAndValidateTargets(targetsInput)
	if err != nil {
		return nil, err
	}
	alive := c.detectAndSaveHosts(targets)
	report := c.generateDetectionReport(targets, alive)
	return map[string]any{
		"targets":    targets,
		"aliveHosts": alive,
		"report":     report,
		"stats":      logic.GetSubnetStats(alive),
	}, nil
}

func (c *DetectionController) parseAndValidateTargets(targetsInput string) ([]string, error) {
	targets := c.parseTargets(targetsInput)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}
	return targets, nil
}

func (c *DetectionController) detectAndSaveHosts(targets []string) []string {
	alive := logic.DetectHosts(targets, 64)
	sort.Strings(alive)
	_ = c.saveAliveHosts(alive)
	return alive
}

func (c *DetectionController) generateDetectionReport(targets, alive []string) string {
	var builder strings.Builder
	builder.WriteString(c.buildStatisticsSummary(targets, alive))
	builder.WriteString("\n")
	builder.WriteString(c.appendSubnetStats(alive))
	return strings.TrimSpace(builder.String())
}

func (c *DetectionController) buildStatisticsSummary(targets, alive []string) string {
	return fmt.Sprintf("targets: %d\nalive: %d", len(targets), len(alive))
}

func (c *DetectionController) appendSubnetStats(alive []string) string {
	stats := logic.GetSubnetStats(alive)
	if len(stats) == 0 {
		return "subnets: none"
	}
	keys := make([]string, 0, len(stats))
	for key := range stats {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := []string{"subnets:"}
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s => %d", key, stats[key]))
	}
	return strings.Join(lines, "\n")
}

func (c *DetectionController) parseTargets(input string) []string {
	return logic.ParseTargetsInput(input)
}

func (c *DetectionController) parseLineToTargets(line string) []string {
	return logic.ParseLineToTargets(line)
}

func (c *DetectionController) parseIPRange(raw string) []string {
	return logic.ParseIPRange(raw)
}

func (c *DetectionController) expandIPRange(raw string) []string {
	return logic.ExpandIPRange(raw)
}

func (c *DetectionController) saveAliveHosts(hosts []string) error {
	if err := c.ensureOutputDir(); err != nil {
		return err
	}
	return c.writeHostsToFile(hosts)
}

func (c *DetectionController) ensureOutputDir() error {
	return util.EnsureDir(util.OutputDir())
}

func (c *DetectionController) writeHostsToFile(hosts []string) error {
	return util.WriteLinesAtomic(filepath.Join(util.OutputDir(), "target.txt"), hosts)
}
