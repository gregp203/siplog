using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace siplog
{
    class FileReader : System.IDisposable
    {
        string _fileName;
        char[] _buffer;
        int _bufferSize;        
        int _positionFile;        
        int _positionBuffer;
        public int lineNumber;
        int _nextLineNum;
        StreamReader sr;

        public FileReader(string fileName,int bufferSize)
        {
            _fileName = fileName;
            _bufferSize = bufferSize;
            _buffer = new char[_bufferSize];            
            _positionFile = 0;
            lineNumber = 0;
            _nextLineNum = 0;
            sr = new StreamReader(_fileName);            
            /*while (sr.Peek() > -1)
            {
                _fileNumChar++;
            }
            _positionFile = sr.ReadBlock(_buffer, 0, _bufferSize) - 1;*/ 
        }
        public string ReadLine()
        {
            string line = null;
            char c = new char();            
            do
            {
                c = _buffer[_positionBuffer];
                line = line + new String(c, 1);
                _positionBuffer++;
                if (_positionBuffer == _bufferSize)
                {
                 _positionFile = _positionFile + (sr.Read(_buffer, 0, _bufferSize) - 1);                        
                 _positionBuffer = 0;                 
                }
            } while (c != '\n');
            lineNumber = _nextLineNum;
            _nextLineNum = lineNumber + 1;
            return line;
        }
        public void Dispose()
        {
            sr.Close();
            sr.Dispose();
            _buffer = null;
            sr = null;
            
        }
    }
}
