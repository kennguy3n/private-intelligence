#ifndef ZKAI_H
#define ZKAI_H

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the AI engine with a cache directory.
 * Returns 0 on success, negative on error. */
int zkai_init(const char *cache_dir);

/* Run a summarization task.
 * Returns a JSON string (must be freed with zkai_free_string) or NULL on error. */
char *zkai_summarize(const char *text, const char *language);

/* Run a translation task.
 * Returns a JSON string (must be freed with zkai_free_string) or NULL on error. */
char *zkai_translate(const char *text, const char *source_lang, const char *target_lang);

/* Run a key-point extraction task.
 * Returns a JSON string (must be freed with zkai_free_string) or NULL on error. */
char *zkai_key_points(const char *text, const char *language);

/* Get the device profile as JSON.
 * Returns a JSON string (must be freed with zkai_free_string) or NULL on error. */
char *zkai_device_profile(void);

/* Shutdown the engine and release all resources. */
int zkai_shutdown(void);

/* Free a string returned by any zkai_* function. */
void zkai_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* ZKAI_H */
