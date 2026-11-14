import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { App } from "./app"
import { AuthGate } from "./auth/auth-gate"
import "github-markdown-css/github-markdown.css"
import "./index.css"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthGate><App /></AuthGate>
  </StrictMode>,
)
