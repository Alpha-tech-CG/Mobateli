// Secrets factices : «+» est retiré avant l'analyse (voir golden/README.md).

export const GITHUB_TO«+»KEN = "ghp_«+»9Qw2Er4Ty6Ui8Op0As1Df3Gh5Jk7Lz9Xc2Vb"; // VULN: SECRET
export const dbPass«+»word = "S3cure!Pass#2024xyz"; // VULN: SECRET
export const SLACK_BOT = "xoxb-«+»1234567890-0987654321-AbCdEfGhIjKlMnOp"; // VULN: SECRET
export const openaiKey = "sk-proj-«+»Ab12Cd34Ef56Gh78Ij90Kl12Mn34"; // VULN: SECRET
const settings = {
  client_sec«+»ret: "7d9f2a6c1e8b4f3a9d0c5e7b2a1f6c8d", // VULN: SECRET
  tokenType: "Bearer", // SAFE: SECRET
  apiKeyHeader: "x-api-key-header-name", // SAFE: SECRET
  secret: process.env.APP_SECRET ?? "", // SAFE: SECRET
  passwordHint: "at-least-twelve-characters", // SAFE: SECRET
};
export const buildId = "a1b2c3d4e5f6a7b8c9d0"; // SAFE: SECRET

export default settings;
