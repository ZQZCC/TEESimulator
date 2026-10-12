package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.os.Parcelable
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

data class KeyIdentifier(val uid: Int, val alias: String)

/** A collection of utility functions to support binder interception. */
object InterceptorUtils {
    private const val EX_SERVICE_SPECIFIC = -8

    private fun synthesizeServiceSpecificMessage(errorCode: Int): String =
        when (errorCode) {
            6 -> "Error::Rc(PERMISSION_DENIED)"
            7 -> "Error::Rc(KEY_NOT_FOUND)"
            else -> if (errorCode > 0) "Error::Rc($errorCode)" else "Error::Km($errorCode)"
        }

    fun createErrorReply(errorCode: Int): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeInt(EX_SERVICE_SPECIFIC)
                writeString(synthesizeServiceSpecificMessage(errorCode))
                writeInt(0)
                writeInt(errorCode)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /**
     * Uses reflection to get the integer transaction code for a given method name from a Stub
     * class. This is necessary for older Android versions where codes are not public constants.
     */
    fun getTransactCode(clazz: Class<*>, method: String): Int {
        return try {
            clazz.getDeclaredField("TRANSACTION_$method").apply { isAccessible = true }.getInt(null)
        } catch (e: Exception) {
            SystemLogger.error(
                "Failed to get transaction code for method '$method' in class '${clazz.simpleName}'.",
                e,
            )
            -1 // Return an invalid code
        }
    }

    /** Creates an `OverrideReply` parcel that indicates success with no data. */
    fun createSuccessReply(): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel = Parcel.obtain().apply { writeNoException() }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a typed array. */
    fun <T : Parcelable> createTypedArrayReply(
        array: Array<T>,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeTypedArray(array, flags)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Creates an `OverrideReply` parcel containing a Parcelable object. */
    fun <T : Parcelable?> createTypedObjectReply(
        obj: T,
        flags: Int = 0,
    ): BinderInterceptor.TransactionResult.OverrideReply {
        val parcel =
            Parcel.obtain().apply {
                writeNoException()
                writeTypedObject(obj, flags)
            }
        return BinderInterceptor.TransactionResult.OverrideReply(parcel)
    }

    /** Checks if a reply parcel contains an exception without consuming it. */
    fun hasException(reply: Parcel): Boolean {
        val exception = runCatching { reply.readException() }.exceptionOrNull()
        if (exception != null) reply.setDataPosition(0)
        return exception != null
    }
}
