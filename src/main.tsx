import React from "react";
import ReactDOM from "react-dom/client";
import { MantineProvider, createTheme } from "@mantine/core";
import App from "./App";
import "@mantine/core/styles.css";
import "@mantine/charts/styles.css";
import "./index.css";

const theme = createTheme({
  fontFamily: "Inter, sans-serif",
  headings: {
    fontFamily: "Outfit, sans-serif",
  },
  primaryColor: "cyan",
  primaryShade: 5,
  colors: {
    // Custom neon palettes matching the Cyber-Premium design guidelines
    cyan: [
      "#e0fbfc",
      "#c2f3f5",
      "#8becf0",
      "#4adeeb",
      "#1cd8e4",
      "#00f0ff", // index 5: neon cyan
      "#00bcd4",
      "#0097a7",
      "#00838f",
      "#006064"
    ],
    violet: [
      "#f3e8ff",
      "#e9d5ff",
      "#d8b4fe",
      "#c084fc",
      "#a855f7", // index 4: neon violet
      "#8b5cf6",
      "#7c3aed",
      "#6d28d9",
      "#5b21b6",
      "#4c1d95"
    ],
    emerald: [
      "#e6fffa",
      "#b2f5ea",
      "#81e6d9",
      "#4fd1c5",
      "#319795",
      "#00ff85", // index 5: neon emerald
      "#00b5ad",
      "#008b8b",
      "#005f5f",
      "#004b4b"
    ],
    pink: [
      "#ffe3ec",
      "#fbb6ce",
      "#f687b3",
      "#ed64a6",
      "#d53f8c",
      "#ff00e5", // index 5: neon pink
      "#b83280",
      "#97266d",
      "#702459",
      "#521b41"
    ]
  }
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <MantineProvider defaultColorScheme="dark" theme={theme}>
      <App />
    </MantineProvider>
  </React.StrictMode>,
);
