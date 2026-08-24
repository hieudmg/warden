export function App() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="border-b px-6 py-4">
        <h1 className="text-xl font-semibold">Warden Hub</h1>
        <p className="text-sm text-muted-foreground">
          tailnet management plane — read-only view of secrets, execution happens on clients
        </p>
      </header>
    </div>
  )
}
