module.exports = {
  apps: [
    {
      name: "ip-scorer",
      script: "ipRiskScorer.py",
      interpreter: "python3",
      watch: ["."],
      watch_delay: 1000,
      autorestart: true,
    },
  ],
};
