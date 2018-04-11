package cognito

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// GetAdminAccessToken makes an admin auth request to cognito and returns an access token
// This is useful for getting credentials for backend services when necessary
// This should probably only be used against a segregated user pool that doesn't have public users
// This will require ADMIN_NO_SRP_AUTH to be enabled an no additional challenges
func GetAdminAccessToken(username, password, clientID, userPoolID string) (string, error) {
	sess := session.Must(session.NewSession())
	cog := cognitoidentityprovider.New(sess, nil)
	req := &cognitoidentityprovider.AdminInitiateAuthInput{
		AuthFlow: aws.String(cognitoidentityprovider.AuthFlowTypeAdminNoSrpAuth),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(username),
			"SECRET_HASH": aws.String(password),
		},
		ClientId:   aws.String(clientID),
		UserPoolId: aws.String(userPoolID),
	}

	resp, err := cog.AdminInitiateAuth(req)
	if err != nil {
		return "", err
	}
	if resp.AuthenticationResult == nil || resp.AuthenticationResult.AccessToken == nil {
		return "", fmt.Errorf("Error initiating auth, authentication result or token was nil")
	}
	return *resp.AuthenticationResult.AccessToken, nil
}
