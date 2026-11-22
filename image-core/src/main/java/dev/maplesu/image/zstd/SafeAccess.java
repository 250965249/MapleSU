/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.maplesu.image.zstd;

/** MapleSU portable byte-array replacement for unzstd SafeAccess. No native or reflective APIs. */
final class SafeAccess {
    private SafeAccess() {}

    static byte getByte(Object base, long offset) {
        return ((byte[]) base)[Math.toIntExact(offset)];
    }

    static short getShort(Object base, long offset) {
        byte[] data = (byte[]) base;
        int at = Math.toIntExact(offset);
        return (short) ((data[at] & 255) | ((data[at + 1] & 255) << 8));
    }

    static int getInt(Object base, long offset) {
        byte[] data = (byte[]) base;
        int at = Math.toIntExact(offset);
        return (data[at] & 255) | ((data[at + 1] & 255) << 8)
                | ((data[at + 2] & 255) << 16) | ((data[at + 3] & 255) << 24);
    }

    static long getLong(Object base, long offset) {
        return (getInt(base, offset) & 0xFFFFFFFFL) | ((long) getInt(base, offset + 4) << 32);
    }

    static void putByte(Object base, long offset, byte value) {
        ((byte[]) base)[Math.toIntExact(offset)] = value;
    }

    static void putShort(Object base, long offset, short value) {
        byte[] data = (byte[]) base;
        int at = Math.toIntExact(offset);
        data[at] = (byte) value; data[at + 1] = (byte) (value >>> 8);
    }

    static void putInt(Object base, long offset, int value) {
        byte[] data = (byte[]) base;
        int at = Math.toIntExact(offset);
        for (int i = 0; i < 4; i++) data[at + i] = (byte) (value >>> (8 * i));
    }

    static void putLong(Object base, long offset, long value) {
        putInt(base, offset, (int) value); putInt(base, offset + 4, (int) (value >>> 32));
    }

    static void copyMemory(Object source, long sourceOffset, Object destination, long destinationOffset, long size) {
        System.arraycopy(source, Math.toIntExact(sourceOffset), destination, Math.toIntExact(destinationOffset), Math.toIntExact(size));
    }
}
