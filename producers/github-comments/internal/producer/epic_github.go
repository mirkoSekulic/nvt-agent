package producer

import (
	"context"
	"fmt"
	"net/url"
)

func (c *GitHubAPIClient) CanControlEpic(ctx context.Context, repo Repository, user GitHubUser) (bool, error) {
	var response struct {
		Permission string     `json:"permission"`
		User       GitHubUser `json:"user"`
	}
	err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/%s/collaborators/%s/permission", url.PathEscape(repo.Owner), url.PathEscape(repo.Name), url.PathEscape(user.Login)), &response)
	if err != nil {
		return false, err
	}
	return response.User.ID == user.ID && (response.Permission == "admin" || response.Permission == "write" || response.Permission == "maintain"), nil
}
