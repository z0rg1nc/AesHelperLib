using System;
using BtmI2p.MiscUtils;

namespace BtmI2p.AesHelper
{
    public class TempByteArray : IDisposable
    {
        public TempByteArray(int size)
        {
            if(size < 0)
                throw new ArgumentOutOfRangeException("size");
            _data = new byte[size];
        }

        public TempByteArray(byte[] initData)
        {
            _data = initData;
        }

        private readonly byte[] _data;
        public byte[] Data{ get { return _data; }}
        public void Dispose()
        {
            for (int i = 0; i < _data.Length; i++)
            {
                _data[i] = 0xff;
            }
        }
    }

    public class AesProtectedByteArray : IDisposable
    {
        private readonly AesKeyIvPair _aesKeyIvPair 
            = AesKeyIvPair.GenAesKeyIvPair();
        private byte[] _encryptedData;
        public AesProtectedByteArray(
            TempByteArray origDataArray
        )
        {
            if(
                origDataArray == null
                || origDataArray.Data == null
            )
                throw new ArgumentNullException();
            _encryptedData 
                = _aesKeyIvPair.EncryptData(
                    origDataArray.Data
                );
            origDataArray.Dispose();
        }

        public TempByteArray TempData
        {
            get
            {
                return new TempByteArray(
                    _aesKeyIvPair.DecryptData(
                        _encryptedData
                    )
                );
            }
            set
            {
                _encryptedData = _aesKeyIvPair.EncryptData(
                    value.Data
                );
            }
        }
        public void Dispose()
        {
            MiscFuncs.GetRandomBytes(_encryptedData);
            _aesKeyIvPair.Dispose();
        }
    }
}
