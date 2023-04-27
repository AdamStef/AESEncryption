using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace AES
{
    public class MainWindowVM : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        public void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private byte[] key;
        private string decryptedText;
        private string encryptedText;
        private string encryptedFilepath;
        private string decryptedFilepath;

        public string Key
        {
            get => BitConverter.ToString(key).Replace("-", "");
            set
            {
                key = Convert.FromHexString(value);
                OnPropertyChanged();
            }
        }
        public string DecryptedText
        {
            get => decryptedText;
            set
            {
                decryptedText = value;
                OnPropertyChanged();
            }
        }

        public string EncryptedText
        {
            get => encryptedText;
            set
            {
                encryptedText = value;
                OnPropertyChanged();
            }
        }

        public string EncryptedFilepath
        {
            get => encryptedFilepath;
            set
            {
                encryptedFilepath = value;
                OnPropertyChanged();
            }
        }

        public string DecryptedFilepath
        {
            get => decryptedFilepath;
            set
            {
                decryptedFilepath = value;
                OnPropertyChanged();
            }
        }

        public bool Key128RadioChecked { get; set; }
        public bool Key192RadioChecked { get; set; }
        public bool Key256RadioChecked { get; set; }

        public ICommand GenerateKeyBtnCommand { get; set; }
        public ICommand EncryptBtnCommand { get; set; }
        public ICommand DecryptBtnCommand { get; set; }
        public ICommand LoadEncryptedFileBtnCommand { get; set; }
        public ICommand LoadDecryptedFileBtnCommand { get; set; }
        public ICommand SaveEncryptedFileBtnCommand { get; set; }
        public ICommand SaveDecryptedFileBtnCommand { get; set; }
        public ICommand EmptyLeftBoxBtnCommand { get; set; }
        public ICommand EmptyRightBoxBtnCommand { get; set; }

        private readonly Aes aes;
        private byte[]? plainText;
        private byte[]? cipheredText;

        public MainWindowVM()
        {
            key = Convert.FromHexString("4D635166546A576E5A72347537782141");
            encryptedFilepath = "";
            decryptedFilepath = "";
            decryptedText = "";
            encryptedText = "";
            Key128RadioChecked = true;
            aes = new Aes();
            GenerateKeyBtnCommand = new RelayCommand(GenerateKeyBtn);
            EncryptBtnCommand = new RelayCommand(EncryptBtn);
            DecryptBtnCommand = new RelayCommand(DecryptBtn);
            LoadEncryptedFileBtnCommand = new RelayCommand(LoadEncryptedFileBtn);
            LoadDecryptedFileBtnCommand = new RelayCommand(LoadDecryptedFileBtn);
            SaveEncryptedFileBtnCommand = new RelayCommand(SaveEncryptedFileBtn);
            SaveDecryptedFileBtnCommand = new RelayCommand(SaveDecryptedFileBtn);
            EmptyLeftBoxBtnCommand = new RelayCommand(EmptyLeftBoxBtn);
            EmptyRightBoxBtnCommand = new RelayCommand(EmptyRightBoxBtn);
        }

        private int GetKeySize()
        {
            if (Key128RadioChecked == true)
            {
                return 128;
            }
            else if (Key192RadioChecked == true)
            {
                return 192;
            }
            else if (Key256RadioChecked == true)
            {
                return 256;
            }
            else throw new AESException("Select key size.");
        }

        private void ShowErrorMessage(string message)
        {
            MessageBox.Show(message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private void GenerateKeyBtn(object param)
        {
            Key = "";
            try
            {
                int keySize = GetKeySize();
                byte[] generatedKey = aes.GenerateKey(keySize);
                Key = BitConverter.ToString(generatedKey).Replace("-", "");
            }
            catch (AESException ex) { ShowErrorMessage(ex.Message); }
        }

        private void EncryptBtn(object param)
        {
            if (DecryptedText == "")
            {
                ShowErrorMessage("Empty text to encrypt");
                return;
            }
            try
            {
                byte[] buffer = aes.Encrypt(Encoding.UTF8.GetBytes(DecryptedText), key);
                EncryptedText = BitConverter.ToString(buffer).Replace("-", "");
            }
            catch (Exception ex)
            {
                ShowErrorMessage(ex.Message);
            }
        }

        private void DecryptBtn(object param)
        {
            if (EncryptedText == "")
            {
                ShowErrorMessage("Empty text to decrypt");
                return;
            }
            try
            {
                byte[] buffer = aes.Decrypt(Convert.FromHexString(EncryptedText), key);
                DecryptedText = Encoding.UTF8.GetString(buffer);
            }
            catch (ArgumentException ex)
            {
                ShowErrorMessage(ex.Message);
            }
        }

        private void LoadDecryptedFileBtn(object param)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                {
                    plainText = File.ReadAllBytes(openFileDialog.FileName);
                    cipheredText = aes.Encrypt(plainText, key);
                    DecryptedText = Encoding.UTF8.GetString(plainText);
                    EncryptedText = BitConverter.ToString(cipheredText).Replace("-", "");
                    DecryptedFilepath = openFileDialog.FileName;
                }
            }
            catch (AESException ex)
            {
                ShowErrorMessage(ex.Message);
            }
            catch (Exception ex)
            {
                ShowErrorMessage(ex.Message);
            }
        }

        private void LoadEncryptedFileBtn(object param)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                if (openFileDialog.ShowDialog() == true)
                {
                    cipheredText = File.ReadAllBytes(openFileDialog.FileName);
                    plainText = aes.Decrypt(cipheredText, key);
                    DecryptedText = Encoding.UTF8.GetString(plainText);
                    EncryptedText = BitConverter.ToString(cipheredText).Replace("-", "");
                    EncryptedFilepath = openFileDialog.FileName;
                }
            }
            catch (ArgumentException ex)
            {
                ShowErrorMessage(ex.Message);
            }
        }

        private void SaveDecryptedFileBtn(object param)
        {
            if (plainText == null || plainText.Length == 0)
            {
                ShowErrorMessage("Nothing to save.");
                return;
            }
            SaveFileDialog saveFileDialog = new();
            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllBytes(saveFileDialog.FileName, plainText);
                }
                catch
                {
                    ShowErrorMessage("Couldnt't save file.");
                }
            }
        }

        private void SaveEncryptedFileBtn(object param)
        {
            if (cipheredText == null || cipheredText.Length == 0)
            {
                ShowErrorMessage("Nothing to save.");
                return;
            }
            SaveFileDialog saveFileDialog = new();
            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    File.WriteAllBytes(saveFileDialog.FileName, cipheredText);
                }
                catch
                {
                    ShowErrorMessage("Couldnt't save file.");
                }
            }
        }

        private void EmptyLeftBoxBtn(object param)
        {
            DecryptedText = "";
        }

        private void EmptyRightBoxBtn(object param)
        {
            EncryptedText = "";
        }
    }
}
