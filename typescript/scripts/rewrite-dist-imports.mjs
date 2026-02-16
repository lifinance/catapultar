import fs from "node:fs/promises";
import path from "node:path";

const distDir = path.resolve("dist");

async function walk(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(fullPath)));
      continue;
    }

    if (fullPath.endsWith(".js") || fullPath.endsWith(".d.ts")) {
      files.push(fullPath);
    }
  }

  return files;
}

function withJsExtension(specifier) {
  if (!specifier.startsWith("./") && !specifier.startsWith("../")) return specifier;
  if (
    specifier.endsWith(".js") ||
    specifier.endsWith(".mjs") ||
    specifier.endsWith(".cjs") ||
    specifier.endsWith(".json") ||
    specifier.endsWith(".node")
  ) {
    return specifier;
  }
  return `${specifier}.js`;
}

function rewrite(content) {
  const fromPattern = /(from\s*["'])(\.{1,2}\/[^"']+)(["'])/g;
  const dynamicImportPattern = /(import\(\s*["'])(\.{1,2}\/[^"']+)(["']\s*\))/g;

  const withFrom = content.replace(fromPattern, (_, prefix, specifier, suffix) => {
    return `${prefix}${withJsExtension(specifier)}${suffix}`;
  });

  return withFrom.replace(
    dynamicImportPattern,
    (_, prefix, specifier, suffix) => {
      return `${prefix}${withJsExtension(specifier)}${suffix}`;
    },
  );
}

const files = await walk(distDir);
await Promise.all(
  files.map(async (file) => {
    const source = await fs.readFile(file, "utf8");
    const updated = rewrite(source);
    if (updated !== source) await fs.writeFile(file, updated);
  }),
);
