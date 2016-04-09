using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace MyCourseWork 
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window 
    {
        public MainWindow() 
        {
            InitializeComponent();
            rbEncrypt.IsChecked = true;
        }

        private void EncryptFile(string inFile) 
        {
            SymmetricAlgorithm algorithm = SymmetricAlgorithm.Create("Rijndael");
            algorithm.Padding = PaddingMode.Zeros;
            algorithm.Mode = CipherMode.CBC;
            algorithm.Key = GetEncPassword();
            algorithm.IV = new Byte[algorithm.IV.Length];
            
            string outFile = inFile + ".enc";

            if (File.Exists(outFile))
            {
                if (MessageBox.Show("Файл уже существует. Перезаписать его?", "Внимание", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                {
                    WriteToEncryptedFile(algorithm, outFile, inFile);
                }
            }
            else
                WriteToEncryptedFile(algorithm, outFile, inFile);
        }

        private void WriteToEncryptedFile(SymmetricAlgorithm algorithm, string outFile, string inFile)
        {
            using (FileStream outFileStream = new FileStream(outFile, FileMode.Create))
            {
                using (CryptoStream outStreamEncrypted = new CryptoStream(outFileStream, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    if (cbGenerateKey.IsChecked == true)
                    {
                        using (FileStream outPassFileStream = new FileStream(inFile + ".key", FileMode.Create))
                        {
                            outPassFileStream.Write(algorithm.Key, 0, algorithm.Key.Length);
                            outPassFileStream.Close();
                        }
                    }

                    int countOfReadAtOnce = 0;
                    int blockSizeBytes = algorithm.BlockSize / 8;
                    Byte[] data = new Byte[blockSizeBytes];

                    using (FileStream inFileStream = new FileStream(inFile, FileMode.Open))
                    {
                        do
                        {
                            countOfReadAtOnce = inFileStream.Read(data, 0, blockSizeBytes);
                            outStreamEncrypted.Write(data, 0, countOfReadAtOnce);
                        }
                        while
                            (countOfReadAtOnce > 0);

                        inFileStream.Close();
                    }
                    outStreamEncrypted.Close();
                }
                outFileStream.Close();
            }
        }

        private void DecryptFile(string inFile) 
        {
            String outFile = inFile.Substring(0, inFile.Length - 4);

            SymmetricAlgorithm algorithm = SymmetricAlgorithm.Create("Rijndael");
            algorithm.Padding = PaddingMode.Zeros;
            algorithm.Mode = CipherMode.CBC;
            algorithm.Key = GetDecPassword();
            algorithm.IV = new Byte[algorithm.IV.Length];

            if (File.Exists(outFile))
            {
                if (MessageBox.Show("Файл уже существует. Перезаписать его?", "Внимание", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                {
                    WriteToDecryptedFile(algorithm, outFile, inFile);
                }
            }
            else
                WriteToDecryptedFile(algorithm, outFile, inFile);
        }

        private void WriteToDecryptedFile(SymmetricAlgorithm algorithm, string outFile, string inFile)
        {
            using (FileStream inFileStream = new FileStream(inFile, FileMode.Open))
            {
                    using (FileStream outFileStream = new FileStream(outFile, FileMode.Create))
                    {
                        int countOfReadAtOnce = 0;

                        int blockSizeBytes = algorithm.BlockSize / 8;
                        Byte[] data = new Byte[blockSizeBytes];

                        using (CryptoStream outStreamDecrypted = new CryptoStream(outFileStream, algorithm.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            do
                            {
                                countOfReadAtOnce = inFileStream.Read(data, 0, blockSizeBytes);
                                outStreamDecrypted.Write(data, 0, countOfReadAtOnce);

                            }
                            while (countOfReadAtOnce > 0);

                            outStreamDecrypted.Close();
                        }
                        outFileStream.Close();
                    }
                    inFileStream.Close();
                }
        }

        private Byte[] GetEncPassword() 
        {
            if (cbGenerateKey.IsChecked == true)
            {
                return GeneratePassword(SymmetricAlgorithm.Create("Rijndael").Key.Length);
            }
            else
            {
                if (btnChooseKey.IsChecked == true)
                {
                    return GetHashFile(tbKeyPath.Text);
                }
                else
                {
                    return GetHashPassword(pbFirst.Password);
                }
            }
        }

        private Byte[] GetDecPassword()
        {
            if (btnChooseKey.IsChecked == true)
            {
                if (tbKeyPath.Text.EndsWith(".key"))
                    return GetHashPasswordToDec(tbKeyPath.Text);
                else
                    return GetHashFile(tbKeyPath.Text);
            }
            else
            {
                return GetHashPassword(pbFirst.Password);
            }
        }

        private Byte[] GetHashPasswordToDec(string inFileKey)
        {
            using(FileStream inFileStream = new FileStream(inFileKey, FileMode.Open))
            {
                Byte[] data = new Byte[32];
                inFileStream.Read(data, 0, 32);
                inFileStream.Close();
                return data;
            }
        }

        private Byte[] GetHashPassword(String textPassword) 
        {
            HashAlgorithm hash = HashAlgorithm.Create("SHA256");
            Byte[] hashedValue = hash.ComputeHash(Encoding.UTF8.GetBytes(textPassword.ToString()));
            return hashedValue;
        }

        private Byte[] GetHashFile(String inFile)
        {
            using (FileStream inFileStream = new FileStream(inFile, FileMode.Open))
            {
                int size = Math.Min(65536, (int)inFileStream.Length);
                Byte[] data = new Byte[size];
                inFileStream.Read(data, 0, size);

                HashAlgorithm hash = HashAlgorithm.Create("SHA256");
                Byte[] hashedValue = hash.ComputeHash(data);
                return hashedValue;
            }
        }

        private Byte[] GeneratePassword(Int32 length)
        {
            RNGCryptoServiceProvider randomNumberGenerate = new RNGCryptoServiceProvider();
            Byte[] randomBytes = new Byte[length];
            randomNumberGenerate.GetBytes(randomBytes);
            return randomBytes;
        }

        private void OpenFileDialog(object sender, RoutedEventArgs e) 
        {
            OpenFileDialog dialog = new OpenFileDialog();
            dialog.ShowDialog();
            tbFilePath.Text = dialog.FileName;
        }

        private void checkedEncrypt(object sender, RoutedEventArgs e) 
        {
            cbGenerateKey.IsEnabled = true;
            actPath.Data = eyeEncrypt.Data;
            actPath.Fill = eyeEncrypt.Fill;
            actPath.Stretch = Stretch.Fill;
            actLabel.Content = "Encrypt";
            pbSecond.IsEnabled = true;
            pbSecond.Clear();
        }

        private void checkedDecrypt(object sender, RoutedEventArgs e) 
        {
            cbGenerateKey.IsChecked = false;
            cbGenerateKey.IsEnabled = false;
            actPath.Data = eyeDecrypt.Data;
            actPath.Fill = eyeDecrypt.Fill;
            actPath.Stretch = Stretch.Fill;
            actLabel.Content = "Decrypt";
            pbSecond.IsEnabled = false;
            pbSecond.Clear();
        }

        private void StartWork(object sender, RoutedEventArgs e) 
        {
            if (File.Exists(tbFilePath.Text)) 
            {
                if (rbEncrypt.IsChecked == true) 
                {
                    if (btnChooseKey.IsChecked == true) 
                    {
                        if (String.Compare(tbFilePath.Text, tbKeyPath.Text) != 0) 
                        {
                            if (File.Exists(tbKeyPath.Text)) 
                            {
                                try 
                                {
                                    EncryptFile(tbFilePath.Text);
                                    tbKeyPath.Clear();
                                } 
                                catch (Exception ex) 
                                {
                                    MessageBox.Show(String.Format("Ошибка при шифровании {0}", ex.Message), "Ошибка");
                                    return;
                                }
                            } 
                            else 
                            {
                                MessageBox.Show("Выбранный файл больше не существует", "Ошибка", MessageBoxButton.OK);
                                btnChooseKey_Unchecked(sender, e);
                            }
                        } 
                        else 
                        {
                            MessageBox.Show("В качестве ключа нельзя использовать сам файл", "Ошибка", MessageBoxButton.OK);
                            btnChooseKey_Unchecked(sender, e);
                        }
                    } 
                    else 
                    {
                        if (pbFirst.Password.Length != 0 || cbGenerateKey.IsChecked == true)
                        {
                            if (String.Compare(pbFirst.Password, pbSecond.Password) == 0)
                            {
                                try
                                {
                                    EncryptFile(tbFilePath.Text);
                                }
                                catch (Exception ex)
                                {
                                    MessageBox.Show(String.Format("Ошибка при шифровании {0}", ex.Message), "Ошибка");
                                    return;
                                }
                            }
                            else
                            {
                                MessageBox.Show("Пароли не совпадают", "Ошибка", MessageBoxButton.OK);
                                pbFirst.Focus();
                            }
                        }
                        else
                        {
                            MessageBox.Show("Пароль не может быть пустым", "Ошибка", MessageBoxButton.OK);
                        }
                        pbFirst.Clear();
                        pbSecond.Clear();
                    }
                }
                if (rbDecrypt.IsChecked == true) 
                {
                    if (tbFilePath.Text.EndsWith(".enc")) 
                    {
                        try 
                        {
                            DecryptFile(tbFilePath.Text);
                        } 
                        catch (Exception ex) 
                        {
                            MessageBox.Show(String.Format("Ошибка в процессе дешифрации {0}", ex.Message), "Ошибка");
                            return;
                        }
                        pbFirst.Clear();
                        tbKeyPath.Clear();
                        btnChooseKey_Unchecked(sender, e);
                    } 
                    else 
                    {
                        MessageBox.Show("Возможно вы хотели зашифровать файл", "Ошибка", MessageBoxButton.OK);
                    }
                }
                if (cbErase.IsChecked == true) 
                {
                    File.Delete(tbFilePath.Text);
                    tbFilePath.Clear();
                }
                
            } 
            else 
            {
                MessageBox.Show("Вы не выбрали файл", "Ошибка", MessageBoxButton.OK);
            }
        }


        private void btnChooseKey_Checked(object sender, RoutedEventArgs e) 
        {
            pbFirst.Clear();
            pbSecond.Clear();

            OpenFileDialog dialog = new OpenFileDialog();
            dialog.ShowDialog();

            pbFirst.IsEnabled = false;
            pbSecond.IsEnabled = false;
            tbKeyPath.Text = dialog.FileName;
        }
        private void btnChooseKey_Unchecked(object sender, RoutedEventArgs e) 
        {
            tbKeyPath.Clear();
            pbFirst.IsEnabled = true;
            pbSecond.IsEnabled = true;
        }

        private void cbGenerateKey_Checked(object sender, RoutedEventArgs e)
        {
            pbFirst.Clear();
            pbSecond.Clear();
            tbKeyPath.Clear();

            btnChooseKey.IsEnabled = false;
            pbFirst.IsEnabled = false;
            pbSecond.IsEnabled = false;
        }

        private void cbGenerateKey_Unchecked(object sender, RoutedEventArgs e)
        {
            pbFirst.Clear();
            pbSecond.Clear();
            tbKeyPath.Clear();

            btnChooseKey.IsEnabled = true;
            pbFirst.IsEnabled = true;
            pbSecond.IsEnabled = true;
        }
    }
}