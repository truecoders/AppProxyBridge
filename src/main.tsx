import React from "react";
import ReactDOM from "react-dom/client";
import { MantineProvider, createTheme } from "@mantine/core";
import App from "./App";
import "@mantine/core/styles.css";
import "@mantine/charts/styles.css";
import "./index.css";

const theme = createTheme({
  fontFamily: "Plus Jakarta Sans, Outfit, sans-serif",
  primaryColor: "violet",
  primaryShade: 7,
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <MantineProvider defaultColorScheme="dark" theme={theme}>
      <App />
    </MantineProvider>
  </React.StrictMode>,
);

