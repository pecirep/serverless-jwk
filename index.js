const { default: generateKeyPair } = require('jose/util/generate_key_pair');
const { default: fromKeyLike } = require('jose/jwk/from_key_like');
const { randomBytes } = require('crypto');
const fs = require('fs');

const entity = 'ServerlessJWK'
const DEBUG = process.env.SLS_DEBUG === '*'

class ServerlessJWKPlugin {
    constructor(serverless, cliOptions) {

        this.error = serverless.classes.Error;
        this.serverless = serverless;
        this.options = serverless.service.custom.jwk;
        this.cliOptions = cliOptions || {};
        this.aws = this.serverless.getProvider('aws');

        this.hooks = {
            //'aws:info:displayStackOutputs': this.printSummary(),
            'jwk:jwk': () => this.serverless.cli.log(this.commands.jwk.usage),
            'jwk:deploy:deploy': this.createAndDeployJWK.bind(this),
            'jwk:remove:remove': this.removeDeployedJWK.bind(this),
            'after:aws:deploy:deploy:updateStack': () => this.serverless.pluginManager.run(['jwk', 'deploy']),
            'before:remove:remove': () => this.serverless.pluginManager.run(['jwk', 'remove']),
        };

        this.commands = {
            jwk: {
                usage: 'Generate and deploy JWK pairs',
                lifecycleEvents: ['jwk', 'deploy'],
                commands: {
                    deploy: {
                        usage: 'Deploy JWK pair',
                        lifecycleEvents: ['deploy']
                    },
                    remove: {
                        usage: 'Removes deployed JWKs',
                        lifecycleEvents: ['remove']
                    }
                }
            }
        };
    }

    validateConfig() {
        //TODO: validate bucketName
    }

    async createAndDeployJWK() {
        const { publicKey, privateKey } = await generateKeyPair('RS256');

        const privateJwk = await fromKeyLike(privateKey);
        const publicJwk = await fromKeyLike(publicKey);

        const kid = randomBytes(32).toString('base64');

        privateJwk.kid = publicJwk.kid = kid;
        privateJwk.use = publicJwk.use = 'sig';
        privateJwk.alg = publicJwk.use = 'sig';

        const ssmPath = this.options?.ssmPath || `/${this.serverless.service.service}-${this.serverless.service.provider.stage}/auth/jwt/privateJWK`

        const putParameterRequest = {
            Name: ssmPath,
            Value: JSON.stringify(privateJwk),
            Type: 'SecureString',
            KeyId: 'alias/aws/ssm',
            Overwrite: true
        }

        const putParameterResponse = await this.aws.request('SSM', 'putParameter', putParameterRequest);
        if (DEBUG) this.serverless.cli.log(`SSM PutParameter response: ${JSON.stringify(putParameterResponse)}`, entity);

        try {
            const latestDeployedJWK = await this.getLatestJwkFromS3();
            const jwks = {keys: [publicJwk, latestDeployedJWK]};
            await this.uploadJwksToS3(jwks);

        } catch(e) {
            const jwks = {keys: [publicJwk]};
            await this.uploadJwksToS3(jwks);
        }

        await this.invalidateCloudfrontJwks(kid);

        this.serverless.cli.log('new jwk pair successfully generated and deployed', entity)

        if (DEBUG) this.savePubKeyToFile(publicKey);
    }

    async getLatestJwkFromS3() {
        const s3getObjectRequest = {
            Bucket: this.options.bucketName,
            Key: '.well-known/jwks.json'
        };
        const getObjectResponse = await this.aws.request('S3', 'getObject', s3getObjectRequest);
        if (DEBUG) this.serverless.cli.log(`S3 getObject response: ${JSON.stringify(getObjectResponse)}`, entity);
        return JSON.parse(getObjectResponse.Body).keys[0];
    }

    async uploadJwksToS3(jwks) {
        const s3putObjectRequest = {
            Bucket: this.options.bucketName,
            ContentType: 'application/json',
            Key: '.well-known/jwks.json',
            Body: JSON.stringify(jwks)
        };
        const putObjectResponse = await this.aws.request('S3', 'putObject', s3putObjectRequest);
        if (DEBUG) this.serverless.cli.log(`S3 putObject response: ${JSON.stringify(putObjectResponse)}`, entity);
    }

    async invalidateCloudfrontJwks(kid) {
        const invlidationRequest = {
            DistributionId: await this.getCloudFrontDistributionId(),
            InvalidationBatch: {
                Paths: {
                    Quantity: 1,
                    Items: [
                        '/.well-known/jwks.json',
                    ]
                },
                CallerReference: kid + ';' + Date.now()
            }
        }
        const invalidationResponse = await this.aws.request('CloudFront', 'createInvalidation', invlidationRequest);
        if (DEBUG) this.serverless.cli.log(`CloudFront createInvalidation response: ${JSON.stringify(invalidationResponse)}`, entity);
        //TODO wait?
    }

    async getCloudFrontDistributionId() {
        const requestParams = {
            StackName: this.aws.naming.getStackName()
        }
        const listResourcesResponse = await this.aws.request('CloudFormation', 'listStackResources', requestParams),
            apiDistribution = listResourcesResponse.StackResourceSummaries
                .find(stack => stack.LogicalResourceId === 'ApiDistribution');

        return !apiDistribution ? null : apiDistribution.PhysicalResourceId;
    };

    savePubKeyToFile(publicKey) {
        const pubKeyPem = publicKey.export({type: 'pkcs1', format: 'pem'});
        fs.writeFileSync('./jwt_pubkey.pem', pubKeyPem);
    }

    removeDeployedJWK() {
        //TODO
    }
}

module.exports = ServerlessJWKPlugin;