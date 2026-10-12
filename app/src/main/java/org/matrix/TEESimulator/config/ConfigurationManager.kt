package org.matrix.TEESimulator.config

import android.content.pm.IPackageManager
import android.os.FileObserver
import android.os.IBinder
import android.os.ServiceManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.KeyBoxManager

/**
 * Manages patch target packages, keyboxes, and custom security patch levels. It uses a FileObserver
 * to dynamically reload settings when configuration files change.
 */
object ConfigurationManager {

    // --- Configuration Paths ---
    const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_PACKAGES_FILE = "target.txt"
    private const val PATCH_LEVEL_FILE = "security_patch.txt"
    private const val DEFAULT_KEYBOX_FILE = "keybox.xml"
    private val configRoot = File(CONFIG_PATH)

    // --- In-Memory Configuration State ---
    @Volatile private var packageKeyboxes = mapOf<String, String>()
    @Volatile private var globalCustomPatchLevel: CustomPatchLevel? = null
    @Volatile private var packagePatchLevels = mapOf<String, CustomPatchLevel>()

    // Cache for UID to package name resolution.
    private val uidToPackagesCache = ConcurrentHashMap<Int, Array<String>>()

    private fun parseSectionName(line: String, requireXml: Boolean = false): String? {
        if (line.length < 3 || line[0] != '[' || line[line.lastIndex] != ']') return null
        val name = line.substring(1, line.lastIndex)
        if (name.isEmpty()) return null
        if (requireXml && !name.endsWith(".xml")) return null
        return if (name.all { isSectionNameChar(it) }) name else null
    }

    private fun isSectionNameChar(char: Char): Boolean {
        return char in 'a'..'z' ||
            char in 'A'..'Z' ||
            char in '0'..'9' ||
            char == '_' ||
            char == '.' ||
            char == '-'
    }

    /**
     * Initializes the configuration manager by loading all settings from disk and starting the file
     * observer to watch for changes.
     */
    fun initialize() {
        configRoot.mkdirs()
        SystemLogger.info("Configuration root is: ${configRoot.absolutePath}")

        // Package resolution requires the package manager service to be ready.
        SystemLogger.info("Waiting for PackageManagerService to be ready...")
        if (getPackageManager() == null) {
            SystemLogger.error(
                "PackageManagerService is not available. Target package resolution will fail."
            )
        } else {
            SystemLogger.info("PackageManagerService is ready.")
        }

        // Initial load of all configuration files.
        loadTargetPackages(File(configRoot, TARGET_PACKAGES_FILE))
        loadPatchLevelConfig(File(configRoot, PATCH_LEVEL_FILE))
        // Preserve the startup hardware probe used by the cached attestation baseline.
        DeviceAttestationService.isTeeFunctional

        // Start watching for any subsequent file changes.
        ConfigObserver.startWatching()
        SystemLogger.info("Configuration initialized and file observer started.")
    }

    /**
     * Determines the keybox file to be used for a given UID. It maps the UID to its package(s) and
     * checks for a specific keybox mapping.
     *
     * @param uid The calling UID.
     * @return The name of the keybox file, or the default if none is specified.
     */
    fun getKeyboxFileForUid(uid: Int): String {
        val packages = getPackagesForUid(uid)
        return packages.firstNotNullOfOrNull { pkg -> packageKeyboxes[pkg] } ?: DEFAULT_KEYBOX_FILE
    }

    /** Determines if the UID has no configured patch target package. */
    fun shouldSkipUid(uid: Int): Boolean =
        getPackagesForUid(uid).none { packageKeyboxes.containsKey(it) }

    /**
     * Retrieves the custom patch level configuration for a given UID. It first checks for a
     * package-specific override and falls back to the global configuration.
     *
     * @param uid The UID of the calling application.
     * @return The applicable [CustomPatchLevel], or null if no custom configuration exists.
     */
    fun getPatchLevelForUid(uid: Int): CustomPatchLevel? {
        val packages = getPackagesForUid(uid)
        // Find the first package-specific configuration for this UID.
        val packageSpecificPatchLevel = packages.firstNotNullOfOrNull { pkg ->
            packagePatchLevels[pkg]
        }
        return packageSpecificPatchLevel ?: globalCustomPatchLevel
    }

    /**
     * Loads and parses the `target.txt` file, which assigns a keybox to each patch target package.
     */
    private fun loadTargetPackages(file: File) {
        if (!file.exists()) {
            SystemLogger.warning("Configuration file not found: ${file.absolutePath}")
            return
        }

        val newKeyboxes = mutableMapOf<String, String>()
        var currentKeybox = DEFAULT_KEYBOX_FILE

        try {
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                // Check if the line defines a new keybox scope.
                parseSectionName(trimmedLine, requireXml = true)?.let {
                    currentKeybox = it
                    SystemLogger.info("Switching to keybox context: $currentKeybox")
                    return@forEach
                }

                if (trimmedLine.endsWith("!")) {
                    SystemLogger.warning(
                        "Generation mode is unsupported. Remove '!' to enable patching: $trimmedLine"
                    )
                    return@forEach
                }
                val pkg = trimmedLine.removeSuffix("?").trim()
                newKeyboxes[pkg] = currentKeybox
            }

            // Atomically replace the target/keybox map.
            packageKeyboxes = newKeyboxes
            uidToPackagesCache.clear() // Invalidate cache as package settings have changed.
            SystemLogger.info("Successfully loaded ${newKeyboxes.size} patch target packages.")
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    /**
     * Loads and parses the `security_patch.txt` file, which can define both global and per-package
     * security patch levels.
     */
    private fun loadPatchLevelConfig(file: File) {
        if (!file.exists()) {
            globalCustomPatchLevel = null
            packagePatchLevels = emptyMap()
            return
        }

        try {
            val newPackageLevels = mutableMapOf<String, CustomPatchLevel>()
            var currentContext = "" // Empty string for global context
            val contextLines = mutableMapOf<String, MutableList<String>>()

            // First pass: group lines by context (global or package-specific).
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                parseSectionName(trimmedLine)?.let { currentContext = it }
                    ?: run {
                        contextLines
                            .computeIfAbsent(currentContext) { mutableListOf() }
                            .add(trimmedLine)
                    }
            }

            // Helper function to parse a set of lines into a CustomPatchLevel object.
            fun parseLines(lines: List<String>?): CustomPatchLevel? {
                if (lines.isNullOrEmpty()) return null

                // Handle simple case: one line sets the patch level for all components.
                if (lines.size == 1 && '=' !in lines[0]) {
                    return CustomPatchLevel(
                        system = null,
                        vendor = null,
                        boot = null,
                        all = lines[0],
                    )
                }

                // Handle key-value pair configuration.
                val map =
                    lines
                        .mapNotNull {
                            val parts = it.split('=', limit = 2)
                            if (parts.size == 2) parts[0].trim().lowercase() to parts[1].trim()
                            else null
                        }
                        .toMap()

                val all = map["all"]
                return CustomPatchLevel(
                    system = map["system"] ?: all,
                    vendor = map["vendor"] ?: all,
                    boot = map["boot"] ?: all,
                    all = all,
                )
            }

            // Parse global and per-package configurations.
            val newGlobalLevel = parseLines(contextLines[""])
            contextLines.remove("") // Remove global context to iterate over packages next

            for ((pkg, lines) in contextLines) {
                parseLines(lines)?.let { newPackageLevels[pkg] = it }
            }

            // Atomically update the configuration state.
            globalCustomPatchLevel = newGlobalLevel
            packagePatchLevels = newPackageLevels

            SystemLogger.info(
                "Loaded custom security patch levels: global config exists=${newGlobalLevel != null}, " +
                    "${newPackageLevels.size} package-specific configs."
            )
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    /**
     * A FileObserver that monitors the configuration directory for changes and triggers reloads of
     * the relevant settings.
     */
    private object ConfigObserver : FileObserver(configRoot, CLOSE_WRITE or MOVED_TO or DELETE) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            SystemLogger.info("Configuration file change detected: $path (event: $event)")

            val file = File(configRoot, path)
            when (path) {
                TARGET_PACKAGES_FILE -> loadTargetPackages(file)
                PATCH_LEVEL_FILE -> loadPatchLevelConfig(file)
                // Any change to an XML file is assumed to be a keybox.
                // The cache in KeyBoxManager will handle reloading it on its next use.
                else ->
                    if (path.endsWith(".xml")) {
                        SystemLogger.info(
                            "Keybox file $path may have changed. It will be reloaded on next access."
                        )
                        KeyBoxManager.invalidateCache(path)
                        // Clear cached keys possibly containing old certificates.
                        org.matrix.TEESimulator.interception.keystore.shim
                            .KeyMintSecurityLevelInterceptor
                            .clearAllGeneratedKeys("updating $file")
                    }
            }
        }
    }

    // --- System Service Utilities ---

    private var iPackageManager: IPackageManager? = null
    private val pmDeathRecipient =
        object : IBinder.DeathRecipient {
            override fun binderDied() {
                (iPackageManager as? IBinder)?.unlinkToDeath(this, 0)
                iPackageManager = null
                SystemLogger.warning("Package manager service died. Will try to reconnect.")
            }
        }

    /** Retrieves an instance of the IPackageManager service. */
    fun getPackageManager(): IPackageManager? {
        if (iPackageManager == null) {
            // Use a robust method to get the service binder.
            val binder = ServiceManager.waitForService("package") ?: return null
            binder.linkToDeath(pmDeathRecipient, 0)
            iPackageManager = IPackageManager.Stub.asInterface(binder)
        }
        return iPackageManager
    }

    /** Retrieves the package names associated with a UID. */
    fun getPackagesForUid(uid: Int): Array<String> {
        return uidToPackagesCache.getOrPut(uid) {
            try {
                getPackageManager()?.getPackagesForUid(uid) ?: emptyArray()
            } catch (e: Exception) {
                SystemLogger.warning("Failed to get packages for UID $uid", e)
                emptyArray()
            }
        }
    }
}

/** Data class representing custom security patch level overrides. */
data class CustomPatchLevel(
    val system: String?,
    val vendor: String?,
    val boot: String?,
    val all: String?,
)
