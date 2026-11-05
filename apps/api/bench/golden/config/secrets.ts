// Secrets factices : «+» est retiré avant l'analyse (voir README).

export const stripeKey = "sk_live_«+»4eC39HqLyjWDarjtT1zdp7dc"; // VULN: SECRET
export const awsKeyId = "AKIA«+»Z7Q3MLD2KXW5PRT4"; // VULN: SECRET
export const githubTo«+»ken = "ghp_«+»R7kq2Lm9Xc4Vb8Nz1Pw6Ts3Jd5Hf0Ga2Ye7U"; // VULN: SECRET
export const anthropicKey = "sk-ant-«+»api03-Qw8eR4tY7uI1oP5aS2dF9gH3jK6lZ0x"; // VULN: SECRET
export const databaseUrl = "postgres«+»://admin:Pr0dPa55w0rd!@db.internal:5432/app"; // VULN: SECRET
export const signingSec«+»ret = "Jx7#kQ2!mZ9@vB4$nW8%"; // VULN: SECRET

const config = {
  api«+»Key: "f3a9c2e7b1d84f6a9e0c5b2d7a1f8e3c", // VULN: SECRET
  password: "changeme", // SAFE: SECRET
  token: process.env.API_TOKEN, // SAFE: SECRET
  clientSecret: "${CLIENT_SECRET}", // SAFE: SECRET
  secret: "<your-secret-here>", // SAFE: SECRET
  passwordField: "password_confirmation_input", // SAFE: SECRET
};

export const sessionTtl = "86400"; // SAFE: SECRET
export const commitSha = "9fceb02d0ae598e95dc970b74767f19372d61af8"; // SAFE: SECRET
export const uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"; // SAFE: SECRET

export default config;
