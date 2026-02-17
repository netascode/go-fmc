package fmc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

// TestClientGet_PagesBasic tests the Client::Get method with pagination.
func TestClientGet_PagesBasic(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// For pagination tests to be readable, we use dummy page size of 3 instead of 1000.
	client.MaxItems = 3

	// First request will be without offset to detect if output is paginated.
	gock.New(testURL).Get("/url").
		Reply(200).
		BodyString(`{"items":[{"this_should_be_ignored":"by_the_client"}],"paging":{"next":["link_to_next_page"]}}`)
	// Following requests will be with offset to get all pages.
	gock.New(testURL).Get("/url").MatchParam("offset", "0").
		Reply(200).
		BodyString(`{"items":[{"name":"object_1","value":"value_1"},{"name":"object_2","value":"value_2"},{"name":"object_3","value":"value_3"}],"paging":{"next":["link_to_next_page"]}}`)
	gock.New(testURL).Get("/url").MatchParam("offset", "3").
		Reply(200).
		BodyString(`{"items":[{"name":"object_4","value":"value_4"},{"name":"object_5","value":"value_5"},{"name":"object_6","value":"value_6"}],"paging":{"next":["link_to_next_page"]}}`)
	gock.New(testURL).Get("/url").MatchParam("offset", "6").
		Reply(200).
		BodyString(`{"items":[{"name":"object_7","value":"value_7"},{"name":"object_8","value":"value_8"}]}`)

	res, err := client.Get("/url")
	assert.NoError(t, err)
	assert.Equal(t, `{"items":[{"name":"object_1","value":"value_1"},{"name":"object_2","value":"value_2"},{"name":"object_3","value":"value_3"},{"name":"object_4","value":"value_4"},{"name":"object_5","value":"value_5"},{"name":"object_6","value":"value_6"},{"name":"object_7","value":"value_7"},{"name":"object_8","value":"value_8"}]}`, res.Raw)
}

// TestClientGet_PagesBasic tests the Client::Get method with pagination, where last page is empty.
func TestClientGet_LastPageEmpty(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	// For pagination tests to be readable, we use dummy page size of 3 instead of 1000.
	client.MaxItems = 3

	// First request will be without offset to detect if output is paginated.
	gock.New(testURL).Get("/url").
		Reply(200).
		BodyString(`{"items":[{"this_should_be_ignored":"by_the_client"}],"paging":{"next":["link_to_next_page"]}}`)
	// Following requests will be with offset to get all pages.
	gock.New(testURL).Get("/url").MatchParam("offset", "0").
		Reply(200).
		BodyString(`{"items":[{"name":"object_1","value":"value_1"},{"name":"object_2","value":"value_2"},{"name":"object_3","value":"value_3"}],"paging":{"next":["link_to_next_page"]}}`)
	gock.New(testURL).Get("/url").MatchParam("offset", "3").
		Reply(200).
		BodyString(`{"items":[{"name":"object_4","value":"value_4"},{"name":"object_5","value":"value_5"},{"name":"object_6","value":"value_6"}],"paging":{"next":["link_to_next_page"]}}`)
	gock.New(testURL).Get("/url").MatchParam("offset", "6").
		Reply(200).
		BodyString(`{"items":[]}`)

	res, err := client.Get("/url")
	assert.NoError(t, err)
	assert.Equal(t, `{"items":[{"name":"object_1","value":"value_1"},{"name":"object_2","value":"value_2"},{"name":"object_3","value":"value_3"},{"name":"object_4","value":"value_4"},{"name":"object_5","value":"value_5"},{"name":"object_6","value":"value_6"}]}`, res.Raw)
}

// TestClientGet_NotPaginatedSite tests the Client::Get method with a non-paginated response.
func TestClientGet_NotPaginatedSite(t *testing.T) {
	defer gock.Off()
	client := authenticatedTestClient()

	gock.New(testURL).Get("/url").
		Reply(200).
		BodyString(`{"items":[{"name":"object_1","value":"value_1"},{"name":"object_2","value":"value_2"}]}`)
	// Deny all further queries.
	gock.New(testURL).Get("/url").
		Reply(400)

	res, err := client.Get("/url")
	assert.NoError(t, err)
	assert.Equal(t, `{"items":[{"name":"object_1","value":"value_1"},{"name":"object_2","value":"value_2"}]}`, res.Raw)
}
