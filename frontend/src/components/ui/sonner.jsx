import { Toaster as SonnerToaster } from 'sonner'

/**
 * Toaster component wrapper for sonner with dark theme styling.
 * Mount once at root level (main.jsx or App.jsx).
 */
export function Toaster() {
  return (
    <SonnerToaster
      theme="dark"
      position="top-right"
      richColors
      closeButton
      toastOptions={{
        duration: 4000,
        style: {
          background: 'hsl(213 33% 16%)',
          border: '1px solid hsl(217 24% 23%)',
          color: 'hsl(218 11% 82%)',
        },
      }}
    />
  )
}
