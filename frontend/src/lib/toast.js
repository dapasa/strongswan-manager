import { toast as sonnerToast } from 'sonner'

/**
 * Toast helper functions with sensible defaults.
 * Wraps sonner's toast API for consistent usage across the app.
 */
export const toast = {
  /**
   * Show a success toast.
   * @param {string} message
   * @param {{ description?: string, duration?: number }} options
   */
  success(message, options = {}) {
    sonnerToast.success(message, {
      duration: 3000,
      ...options,
    })
  },

  /**
   * Show an error toast. Accepts a string or an Error/axios error object.
   * @param {string} message
   * @param {{ description?: string, duration?: number }} options
   */
  error(message, options = {}) {
    sonnerToast.error(message, {
      duration: 5000,
      ...options,
    })
  },

  /**
   * Show an info toast.
   * @param {string} message
   * @param {{ description?: string, duration?: number }} options
   */
  info(message, options = {}) {
    sonnerToast.info(message, {
      duration: 4000,
      ...options,
    })
  },

  /**
   * Show a warning toast.
   * @param {string} message
   * @param {{ description?: string, duration?: number }} options
   */
  warning(message, options = {}) {
    sonnerToast.warning(message, {
      duration: 4000,
      ...options,
    })
  },
}

/**
 * Extract a human-readable error message from an axios error or generic Error.
 * @param {Error|object} error
 * @returns {string}
 */
/**
 * Format a single FastAPI validation error into a readable string.
 * Input shape: { type, loc: [...], msg, input }
 */
function formatValidationError(err) {
  const field = err.loc
    ?.filter((seg) => seg !== 'body')
    .join(' → ') || 'unknown field'
  return `${field}: ${err.msg}`
}

/**
 * Extract a human-readable error message from an axios error or generic Error.
 * Handles FastAPI validation error arrays (422) and plain detail strings.
 * @param {Error|object} error
 * @returns {string}
 */
export function getErrorMessage(error) {
  if (!error) return 'An unknown error occurred'

  // Axios error with API response
  const detail = error?.response?.data?.detail
  if (detail) {
    if (typeof detail === 'string') return detail

    // FastAPI validation errors: detail is an array of { type, loc, msg, input }
    if (Array.isArray(detail)) {
      const messages = detail.map(formatValidationError)
      return messages.length === 1
        ? messages[0]
        : messages.map((m) => `• ${m}`).join('\n')
    }

    // Object with message property
    if (detail.message || detail.msg) return detail.message || detail.msg

    return JSON.stringify(detail)
  }

  // Standard error message
  if (error.message) return error.message

  return 'An unknown error occurred'
}
