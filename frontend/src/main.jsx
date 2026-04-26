import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { AuthProvider } from 'react-oidc-context'
import { queryClient } from '@/lib/queryClient'
import { oidcConfig } from '@/config/auth'
import { AuthContextProvider } from '@/contexts/AuthContext'
import { Toaster } from '@/components/ui/sonner'
import App from './App'
import './index.css'

const isBypass = import.meta.env.VITE_AUTH_BYPASS === 'true'

function Root() {
  const inner = (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthContextProvider>
          <App />
        </AuthContextProvider>
      </BrowserRouter>
      <Toaster />
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  )

  // In bypass mode, skip the OIDC AuthProvider entirely
  if (isBypass) {
    return inner
  }

  return <AuthProvider {...oidcConfig}>{inner}</AuthProvider>
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
)
