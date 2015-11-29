using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using BtmI2p.MiscUtil.Conversion;
using BtmI2p.MiscUtil.IO;
using BtmI2p.MiscUtils;
using NLog;
using Xunit;

namespace BtmI2p.AesHelper
{
    public class AesKeyIvPair : IDisposable
    {
        public byte[] Key = new byte[32];
        public byte[] Iv = new byte[16];

        public byte[] ToBinaryArray()
        {
            Assert.NotNull(Key);
            Assert.NotNull(Iv);
            Assert.Equal(Key.Length,32);
            Assert.Equal(Iv.Length,16);
            return Key.Concat(Iv).ToArray();
        }

        public static AesKeyIvPair FromBinaryArray(byte[] bAr)
        {
            Assert.NotNull(bAr);
            Assert.Equal(bAr.Length,48);
            var key = bAr.Take(32).ToArray();
            var iv = bAr.Skip(32).Take(16).ToArray();
            return new AesKeyIvPair()
            {
                Key = key,
                Iv = iv
            };
        }

        public byte[] EncryptData(byte[] data)
        {
            var key = Key;
            var iv = Iv;
            using (var aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform encryptor 
                    = aesAlg.CreateEncryptor(
                        aesAlg.Key, 
                        aesAlg.IV
                    );
                using (var msEncrypt = new MemoryStream(data.Length + 32))
                {
                    using (
                        var csEncrypt = new CryptoStream(
                            msEncrypt, 
                            encryptor, 
                            CryptoStreamMode.Write
                        )
                    )
                    {
                        using (
                            var writer = new EndianBinaryWriter(
                                _littleConverter, 
                                csEncrypt
                            )
                        )
                        {
                            using (var mySha256 = new SHA256Managed())
                            {
                                writer.Write(mySha256.ComputeHash(data));
                            }
                            writer.Write(data);
                        }
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        public enum EDecryptDataErrCodes
        {
            WrongEncryptedDataLength,
            WrongDecryptedDataHash,
            WrongKey
        }
        public byte[] DecryptData(
            byte[] encryptedData
        )
        {
            var key = Key;
            Assert.NotNull(key);
            var iv = Iv;
            Assert.NotNull(iv);
            using (var aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform decryptor 
                    = aesAlg.CreateDecryptor(
                        aesAlg.Key, 
                        aesAlg.IV
                    );
                /**/
                using (var input = new MemoryStream(encryptedData))
                {
                    using (var output = new MemoryStream(
                        encryptedData.Length + 32)
                    )
                    {
                        using (var disposableBuffer = new TempByteArray(4096))
                        {
                            var buffer = disposableBuffer.Data;
                            try
                            {
                                using (
                                    var csDecrypt = new CryptoStream(
                                        input,
                                        decryptor,
                                        CryptoStreamMode.Read
                                    )
                                )
                                {
                                    var read = csDecrypt.Read(buffer, 0, buffer.Length);
                                    while (read > 0)
                                    {
                                        output.Write(buffer, 0, read);
                                        read = csDecrypt.Read(buffer, 0, buffer.Length);
                                    }
                                }
                            }
                            catch (CryptographicException cryptExc)
                            {
                                throw EnumException.Create(
                                    EDecryptDataErrCodes.WrongKey,
                                    innerException: cryptExc
                                );
                            }
                        }
                        var totalLength = (int)output.Length;
                        if (totalLength < 32)
                            throw EnumException.Create(
                                EDecryptDataErrCodes.WrongEncryptedDataLength);
                        output.Seek(0, SeekOrigin.Begin);
                        using (
                            var reader = new EndianBinaryReader(
                                _littleConverter,
                                output
                            )
                        )
                        {
                            using (
                                var tempDataHash
                                    = new TempByteArray(
                                        reader.ReadBytesOrThrow(32)
                                    )
                                )
                            {
                                var data = reader.ReadBytesOrThrow(totalLength - 32);
                                using (var mySha256 = new SHA256Managed())
                                {
                                    var computedDataHash
                                        = mySha256.ComputeHash(data);
                                    if (
                                        tempDataHash.Data.SequenceEqual(
                                            computedDataHash
                                        )
                                    )
                                        return data;
                                }
                                throw EnumException.Create(
                                    EDecryptDataErrCodes.WrongDecryptedDataHash
                                );
                            }
                        }
                    }
                }
            }
        }
        private static readonly Logger _logger 
            = LogManager.GetCurrentClassLogger();
        private static readonly LittleEndianBitConverter _littleConverter 
            = new LittleEndianBitConverter();

        public static AesKeyIvPair GenAesKeyIvPair()
        {
            var result = new AesKeyIvPair();
            MiscFuncs.GetRandomBytes(result.Iv);
            MiscFuncs.GetRandomBytes(result.Key);
            return result;
        }

        public void Dispose()
        {
            MiscFuncs.GetRandomBytes(Key);
            MiscFuncs.GetRandomBytes(Iv);
        }
    }
}
