// AWS Credentials Simulator
class AWSCredentialsSimulator {
    constructor() {
        this.roles = {
            patient: {
                roleArn: 'arn:aws:iam::241743745664:role/PatientRole',
                policy: 'PatientPolicy',
                permissions: [
                    's3:GetObject',
                    'rds:connect',
                    'logs:describe*',
                    'secretsmanager:GetSecretValue'
                ],
                mfaRequired: true
            },
            doctor: {
                roleArn: 'arn:aws:iam::241743745664:role/DoctorRole',
                policy: 'DoctorPolicy',
                permissions: [
                    's3:*',
                    'rds:*',
                    'logs:*',
                    'cloudtrail:LookupEvents',
                    'secretsmanager:*',
                    'kms:Decrypt'
                ],
                mfaRequired: true
            },
            admin: {
                roleArn: 'arn:aws:iam::241743745664:role/AdminRole',
                policy: 'AdminPolicy',
                permissions: ['*'],
                mfaRequired: true
            }
        };
    }

    // Simulate AssumeRole with MFA
    async assumeRole(roleName, mfaCode) {
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                // MFA validation
                if (!this.validateMFA(mfaCode)) {
                    reject(new Error('Invalid MFA code. Please try again.'));
                    return;
                }

                // Generate temporary credentials
                const credentials = {
                    AccessKeyId: 'ASIA' + this.generateRandomString(16).toUpperCase(),
                    SecretAccessKey: this.generateRandomString(40),
                    SessionToken: this.generateRandomString(200),
                    Expiration: new Date(Date.now() + 3600000).toISOString(),
                    RoleArn: this.roles[roleName].roleArn,
                    Policy: this.roles[roleName].policy
                };

                // Store in session
                sessionStorage.setItem('awsCredentials', JSON.stringify(credentials));
                sessionStorage.setItem('currentRole', roleName);
                sessionStorage.setItem('iamPermissions', JSON.stringify(this.roles[roleName].permissions));
                sessionStorage.setItem('mfaVerified', 'true');

                resolve(credentials);
            }, 1000);
        });
    }

    // Validate MFA (simulated)
    validateMFA(code) {
        // In real scenario, this would call AWS STS
        return code && code.length === 6 && /^\d+$/.test(code);
    }

    // Get current credentials
    getCurrentCredentials() {
        const creds = sessionStorage.getItem('awsCredentials');
        return creds ? JSON.parse(creds) : null;
    }

    // Check permission
    checkPermission(action) {
        const permissions = JSON.parse(sessionStorage.getItem('iamPermissions') || '[]');
        const role = sessionStorage.getItem('currentRole');
        
        if (role === 'admin') return true;
        if (permissions.includes('*')) return true;
        
        // Wildcard matching for permissions
        for (const perm of permissions) {
            if (perm.includes('*')) {
                const pattern = perm.replace('*', '.*');
                if (new RegExp(`^${pattern}$`).test(action)) {
                    return true;
                }
            } else if (perm === action) {
                return true;
            }
        }
        return false;
    }

    // Generate random string for credentials
    generateRandomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    // Simulate AWS API call
    async simulateAWSCall(service, action, params = {}) {
        if (!this.getCurrentCredentials()) {
            throw new Error('No active AWS session. Please login.');
        }

        if (!this.checkPermission(`${service}:${action}`)) {
            throw new Error(`AccessDenied: Not authorized to perform ${service}:${action}`);
        }

        // Simulate API call delay
        return new Promise(resolve => {
            setTimeout(() => {
                resolve({
                    ResponseMetadata: { RequestId: this.generateRandomString(16) },
                    ...this.generateMockResponse(service, action, params)
                });
            }, 500);
        });
    }

    // Generate mock responses
    generateMockResponse(service, action, params) {
        switch(service) {
            case 's3':
                return this.generateS3Response(action, params);
            case 'rds':
                return this.generateRDSResponse(action, params);
            case 'cloudtrail':
                return this.generateCloudTrailResponse(action, params);
            case 'iam':
                return this.generateIAMResponse(action, params);
            default:
                return { Status: 'Success' };
        }
    }

    generateS3Response(action, params) {
        switch(action) {
            case 'ListBuckets':
                return {
                    Buckets: [
                        { Name: 'patient-portal-medical-records-hamid', CreationDate: new Date().toISOString() },
                        { Name: 'patient-portal-backups', CreationDate: new Date(Date.now() - 86400000).toISOString() }
                    ],
                    Owner: { DisplayName: 'healthsecure-admin' }
                };
            case 'GetObject':
                return {
                    Body: 'Medical record content...',
                    LastModified: new Date().toISOString(),
                    ContentType: 'application/pdf',
                    Metadata: { patientId: 'PAT-001', doctorId: 'DOC-001' }
                };
            case 'PutObject':
                return {
                    ETag: '"' + this.generateRandomString(32) + '"',
                    VersionId: this.generateRandomString(20)
                };
            default:
                return { Success: true };
        }
    }

    generateRDSResponse(action, params) {
        switch(action) {
            case 'DescribeDBInstances':
                return {
                    DBInstances: [{
                        DBInstanceIdentifier: 'patient-portal-db',
                        DBInstanceClass: 'db.t3.micro',
                        Engine: 'postgres',
                        DBInstanceStatus: 'available',
                        Endpoint: { Address: 'patient-portal-db.cdbpcsd1krxj.ap-southeast-1.rds.amazonaws.com', Port: 5432 },
                        StorageEncrypted: true,
                        KmsKeyId: 'arn:aws:kms:ap-southeast-1:241743745664:key/1234abcd-12ab-34cd-56ef-1234567890ab'
                    }]
                };
            default:
                return { Success: true };
        }
    }

    generateCloudTrailResponse(action, params) {
        return {
            Events: [
                {
                    EventId: this.generateRandomString(16),
                    EventName: 'AssumeRole',
                    EventTime: new Date().toISOString(),
                    Username: 'gc.hamid',
                    Resources: [{ ResourceType: 'AWS::IAM::Role', ResourceName: 'PatientRole' }]
                },
                {
                    EventId: this.generateRandomString(16),
                    EventName: 'GetObject',
                    EventTime: new Date(Date.now() - 300000).toISOString(),
                    Username: 'doctor.user',
                    Resources: [{ ResourceType: 'AWS::S3::Object', ResourceName: 'medical-reports/patient001.pdf' }]
                }
            ]
        };
    }

    generateIAMResponse(action, params) {
        switch(action) {
            case 'ListUsers':
                return {
                    Users: [
                        { UserName: 'patient.user', CreateDate: new Date(Date.now() - 86400000).toISOString() },
                        { UserName: 'doctor.user', CreateDate: new Date(Date.now() - 172800000).toISOString() },
                        { UserName: 'admin.user', CreateDate: new Date(Date.now() - 259200000).toISOString() }
                    ]
                };
            default:
                return { Success: true };
        }
    }

    // Logout
    logout() {
        sessionStorage.removeItem('awsCredentials');
        sessionStorage.removeItem('currentRole');
        sessionStorage.removeItem('iamPermissions');
        sessionStorage.removeItem('mfaVerified');
        window.location.href = 'index.html';
    }
}

// Global instance
const awsSimulator = new AWSCredentialsSimulator();
