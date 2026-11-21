package dev.octoshrimpy.quik.blocking

import javax.inject.Inject
import javax.inject.Singleton

/**
 * SynAck SMS uses only its built-in on-device blocked-number repository.
 * No third-party blocking applications or cross-app number lookups.
 */
@Singleton
class BlockingManager @Inject constructor(
    private val localBlockingClient: QksmsBlockingClient
) : BlockingClient by localBlockingClient
