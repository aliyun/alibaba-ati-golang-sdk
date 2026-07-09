package registry

import (
	"fmt"

	"github.com/aliyun/alibaba-ati-golang-sdk/models"
)

// validateRequired checks that a required string parameter is not empty.
func validateRequired(name, value string) error {
	if value == "" {
		return fmt.Errorf("%w: %s cannot be empty", models.ErrBadRequest, name)
	}
	return nil
}
