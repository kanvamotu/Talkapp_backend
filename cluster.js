const cluster = require("cluster");
const os = require("os");

if (cluster.isPrimary) {
  const cpuCount = os.cpus().length;
  for (let i = 0; i < cpuCount; i++) cluster.fork();
} else {
  require("./server");
}
