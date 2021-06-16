package credentials

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/newrelic/newrelic-lambda-extension/util"

	"github.com/newrelic/newrelic-lambda-extension/config"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/aws/aws-sdk-go/service/ssm/ssmiface"
)

type licenseKeySecret struct {
	LicenseKey string
}

var (
	sess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	secrets    secretsmanageriface.SecretsManagerAPI
	parameters ssmiface.SSMAPI
)

const defaultSecretId = "NEW_RELIC_LICENSE_KEY"
const defaultSSMId = "NEW_RELIC_LICENSE_KEY"

func init() {
	secrets = secretsmanager.New(sess)
	parameters = ssm.New(sess) // TODO different  name
}

func getLicenseKeySecretId(conf *config.Configuration) string {
	if conf.LicenseKeySecretId != "" {
		util.Logln("Fetching license key from secret id " + conf.LicenseKeySecretId)
		return conf.LicenseKeySecretId
	}

	return defaultSecretId
}

func getLicenseSSMParameter(conf *config.Configuration) string {
	// if conf.LicenseKeySecretId != "" {
	// 	util.Logln("Fetching license key from secret id " + conf.LicenseKeySecretId)
	// 	return conf.LicenseKeySecretId
	// }

	return defaultSecretId
}

func decodeLicenseKey(rawJson *string) (string, error) {
	var secrets licenseKeySecret

	err := json.Unmarshal([]byte(*rawJson), &secrets)
	if err != nil {
		return "", err
	}
	if secrets.LicenseKey == "" {
		return "", fmt.Errorf("malformed license key secret; missing \"LicenseKey\" attribute")
	}

	return secrets.LicenseKey, nil
}

// IsSecretConfigured returns true if the Secrets Manager secret is configured, false
// otherwise
func IsSecretConfigured(conf *config.Configuration) bool {
	secretId := getLicenseKeySecretId(conf)
	secretValueInput := secretsmanager.GetSecretValueInput{SecretId: &secretId}

	_, err := secrets.GetSecretValue(&secretValueInput)
	if err != nil {
		return false
	}

	return true
}

// GetNewRelicLicenseKey fetches the license key from AWS Secrets Manager, falling back
// to the NEW_RELIC_LICENSE_KEY environment variable if set.
func GetNewRelicLicenseKey(conf *config.Configuration) (string, error) {
	if conf.LicenseKey != "" {
		util.Logln("Using license key from environment variable")
		return conf.LicenseKey, nil
	}

	// Try SecretsManager first
	secretId := getLicenseKeySecretId(conf)
	secretValueInput := secretsmanager.GetSecretValueInput{SecretId: &secretId}

	secretValueOutput, err := secrets.GetSecretValue(&secretValueInput)
	if err == nil {
		return decodeLicenseKey(secretValueOutput.SecretString)
	}

	// Then SSM Parameter Store
	withDecryption := true
	parameterValueInput := ssm.GetParameterInput{
		Name:           &secretId,
		WithDecryption: &withDecryption,
	}
	parameterValueOutput, err := parameters.GetParameter(&parameterValueInput)
	if err == nil {
		return *parameterValueOutput.Parameter.Value, nil
	}

	// Then pull from the environment
	envLicenseKey, found := os.LookupEnv(defaultSecretId)
	if found {
		return envLicenseKey, nil
	}

	// TODO: return SecretManager error
	return "", err
}

// OverrideSecretsManager overrides the default Secrets Manager implementation
func OverrideSecretsManager(override secretsmanageriface.SecretsManagerAPI) {
	secrets = override
}
