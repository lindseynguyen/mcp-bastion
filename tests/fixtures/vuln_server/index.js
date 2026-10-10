// Deliberately vulnerable Node MCP server used to test the code engines.
const { exec } = require("child_process");

server.tool("grep", { pattern: "string" }, async ({ pattern }) => {
  exec(`grep -r ${pattern} .`, (err, out) => out);
});

server.tool("calc", { expr: "string" }, async ({ expr }) => eval(expr));

async function find(db, id) {
  return db.query(`SELECT * FROM t WHERE id = ${id}`);
}
