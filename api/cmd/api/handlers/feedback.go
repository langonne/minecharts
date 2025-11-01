package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"minecharts/cmd/auth"
	"minecharts/cmd/config"
	"minecharts/cmd/logging"

	"github.com/gin-gonic/gin"
)

const (
	feedbackTypeBug     = "bug"
	feedbackTypeFeature = "feature"
	feedbackTypeOther   = "other"

	maxFeedbackTitleLength       = 140
	maxFeedbackDescriptionLength = 5000
	maxFeedbackEmailLength       = 320
	maxFeedbackURLLength         = 2048
	githubRequestTimeout         = 10 * time.Second
)

var feedbackTypeLabels = map[string]string{
	feedbackTypeBug:     "bug",
	feedbackTypeFeature: "enhancement",
	feedbackTypeOther:   "feedback",
}

// FeedbackRequest represents the payload sent by the frontend to report a bug or request a feature.
type FeedbackRequest struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Email         string `json:"email"`
	PageURL       string `json:"page_url"`
	ScreenshotURL string `json:"screenshot_url"`
}

type githubIssueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels,omitempty"`
}

type githubIssueResponse struct {
	HTMLURL string `json:"html_url"`
	Number  int    `json:"number"`
}

// SubmitFeedbackHandler handles incoming feedback submissions and proxies them to GitHub Issues.
func SubmitFeedbackHandler(c *gin.Context) {
	if !config.FeedbackEnabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "feedback endpoint is disabled"})
		return
	}

	user, ok := auth.GetCurrentUser(c)
	if !ok {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", "not_authenticated",
		).Warn("Feedback submission failed: missing authentication context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	var req FeedbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", err.Error(),
		).Warn("Feedback submission failed: invalid JSON payload")
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
		return
	}

	if err := validateFeedbackRequest(&req); err != nil {
		logging.API.InvalidRequest.WithFields(
			"path", c.Request.URL.Path,
			"remote_ip", c.ClientIP(),
			"error", err.Error(),
		).Warn("Feedback submission failed: validation error")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	normalizedType := normalizeFeedbackType(req.Type)
	title := strings.TrimSpace(req.Title)
	description := strings.TrimSpace(req.Description)

	labels := buildFeedbackLabels(normalizedType)
	body := buildFeedbackBody(normalizedType, description, req.Email, req.PageURL, req.ScreenshotURL, user.ID, user.Username)

	ctx, cancel := context.WithTimeout(c.Request.Context(), githubRequestTimeout)
	defer cancel()

	logging.API.Feedback.WithFields(
		"type", normalizedType,
		"title", title,
		"remote_ip", c.ClientIP(),
		"user_id", user.ID,
		"username", user.Username,
	).Info("Forwarding feedback to GitHub issues")

	issueURL, issueNumber, err := createGitHubIssue(ctx, title, body, labels)
	if err != nil {
		logging.API.Feedback.WithFields(
			"type", normalizedType,
			"remote_ip", c.ClientIP(),
			"error", err.Error(),
		).Error("Failed to create GitHub issue for feedback")
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to submit feedback"})
		return
	}

	logging.API.Feedback.WithFields(
		"type", normalizedType,
		"issue_number", issueNumber,
		"issue_url", issueURL,
	).Info("Feedback submitted successfully")

	c.JSON(http.StatusCreated, gin.H{
		"issue_url":    issueURL,
		"issue_number": issueNumber,
	})
}

func normalizeFeedbackType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case feedbackTypeBug:
		return feedbackTypeBug
	case feedbackTypeFeature:
		return feedbackTypeFeature
	default:
		return feedbackTypeOther
	}
}

func validateFeedbackRequest(req *FeedbackRequest) error {
	if req == nil {
		return errors.New("request is required")
	}

	req.Type = strings.TrimSpace(req.Type)
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	req.Email = strings.TrimSpace(req.Email)
	req.PageURL = strings.TrimSpace(req.PageURL)
	req.ScreenshotURL = strings.TrimSpace(req.ScreenshotURL)

	if req.Title == "" {
		return errors.New("title is required")
	}
	if len(req.Title) > maxFeedbackTitleLength {
		return fmt.Errorf("title must be shorter than %d characters", maxFeedbackTitleLength)
	}

	if req.Description == "" {
		return errors.New("description is required")
	}
	if len(req.Description) > maxFeedbackDescriptionLength {
		return fmt.Errorf("description must be shorter than %d characters", maxFeedbackDescriptionLength)
	}

	if req.Email != "" && len(req.Email) > maxFeedbackEmailLength {
		return fmt.Errorf("email must be shorter than %d characters", maxFeedbackEmailLength)
	}

	if req.PageURL != "" && len(req.PageURL) > maxFeedbackURLLength {
		return fmt.Errorf("page_url must be shorter than %d characters", maxFeedbackURLLength)
	}

	if req.ScreenshotURL != "" && len(req.ScreenshotURL) > maxFeedbackURLLength {
		return fmt.Errorf("screenshot_url must be shorter than %d characters", maxFeedbackURLLength)
	}

	return nil
}

func buildFeedbackLabels(feedbackType string) []string {
	defaultLabels := splitAndCleanLabels(config.FeedbackGitHubLabels)

	var labels []string
	if len(defaultLabels) > 0 {
		labels = append(labels, defaultLabels...)
	}

	if typeLabel, ok := feedbackTypeLabels[feedbackType]; ok {
		labels = appendIfMissing(labels, typeLabel)
	}

	return labels
}

func buildFeedbackBody(feedbackType, description, email, pageURL, screenshotURL string, userID int64, username string) string {
	var builder strings.Builder

	builder.WriteString("### Feedback Type\n")
	builder.WriteString(fmt.Sprintf("- %s\n\n", humanizeFeedbackType(feedbackType)))

	builder.WriteString("### Description\n")
	builder.WriteString(description)
	builder.WriteString("\n\n")

	builder.WriteString("### Reporter Details\n")
	if email != "" {
		builder.WriteString(fmt.Sprintf("- Email: %s\n", email))
	} else {
		builder.WriteString("- Email: (not provided)\n")
	}
	if pageURL != "" {
		builder.WriteString(fmt.Sprintf("- Page URL: %s\n", pageURL))
	}
	if screenshotURL != "" {
		builder.WriteString(fmt.Sprintf("- Screenshot: %s\n", screenshotURL))
	}
	builder.WriteString(fmt.Sprintf("- Reporter ID: %d\n", userID))
	builder.WriteString(fmt.Sprintf("- Reporter Username: %s\n", username))

	return builder.String()
}

func createGitHubIssue(ctx context.Context, title, body string, labels []string) (string, int, error) {
	issuePayload := githubIssueRequest{
		Title:  title,
		Body:   body,
		Labels: labels,
	}

	payload, err := json.Marshal(issuePayload)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal issue payload: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", config.FeedbackGitHubRepoOwner, config.FeedbackGitHubRepoName)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create GitHub request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.FeedbackGitHubToken))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{
		Timeout: githubRequestTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", 0, fmt.Errorf("failed to read GitHub response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", 0, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var issueResp githubIssueResponse
	if err := json.Unmarshal(bodyBytes, &issueResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode GitHub response: %w", err)
	}

	return issueResp.HTMLURL, issueResp.Number, nil
}

func splitAndCleanLabels(labels string) []string {
	if labels == "" {
		return nil
	}

	parts := strings.Split(labels, ",")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		label := strings.TrimSpace(part)
		if label != "" {
			cleaned = appendIfMissing(cleaned, label)
		}
	}
	return cleaned
}

func appendIfMissing(slice []string, candidate string) []string {
	for _, existing := range slice {
		if strings.EqualFold(existing, candidate) {
			return slice
		}
	}
	return append(slice, candidate)
}

func humanizeFeedbackType(t string) string {
	switch t {
	case feedbackTypeBug:
		return "Bug"
	case feedbackTypeFeature:
		return "Feature Request"
	default:
		return "Other"
	}
}
