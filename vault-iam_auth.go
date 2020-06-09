package vault_iam_auth

import (
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/aws"
)

func VaultEC2Login(vaultAddr string, vaultRole string) (secret *api.Secret, err error) {
	loginData := make(map[string]interface{})
	loginData, err = awsauth.GenerateLoginData(nil, "", "us-east-1")
	if err != nil {
		return
	}
	loginData["role"] = vaultRole

	client, err := api.NewClient(&api.Config{Address: vaultAddr})
	if err != nil {
		return
	}
	secret, err = client.Logical().Write("auth/aws/login", loginData)
	if err != nil {
		return
	}

	return
}

func VaultLambdaLogin(vaultAddr string, lambdaRole string, vaultRole string) (secret *api.Secret, err error) {
	sess := session.Must(session.NewSession())
	cred := stscreds.NewCredentials(sess, lambdaRole)
	loginData := make(map[string]interface{})
	loginData, err = awsauth.GenerateLoginData(cred, "", "us-east-1")
	if err != nil {
		return
	}
	loginData["role"] = vaultRole

	client, err := api.NewClient(&api.Config{Address: vaultAddr})
	if err != nil {
		return
	}
	secret, err = client.Logical().Write("auth/aws/login", loginData)
	if err != nil {
		return
	}

	return
}
