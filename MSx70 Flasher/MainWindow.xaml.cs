﻿using System;
using System.Configuration;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.ComponentModel;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using EdiabasLib;

namespace MSx70_Flasher
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);

        [FlagsAttribute]
        public enum EXECUTION_STATE : uint
        {
            ES_AWAYMODE_REQUIRED = 0x00000040,
            ES_CONTINUOUS = 0x80000000,
            ES_DISPLAY_REQUIRED = 0x00000002,
            ES_SYSTEM_REQUIRED = 0x00000001
            // Legacy flag, should not be used.
            // ES_USER_PRESENT = 0x00000004
        }


        public MainWindow()
        {
            InitializeComponent();
        }

        private void FlashRSA_Bypass_Fast_Click(object sender, RoutedEventArgs e)
        {
            Flashfull(true);
        }

        private void AppExit_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void IdentifyDME_Click(object sender, RoutedEventArgs e)
        {
            UpdateProgressBar(0);
            IdentDME();
        }

        private void LoadSGBD_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileDialog = new OpenFileDialog();

            fileDialog.InitialDirectory = (Global.ecuPath);
            fileDialog.Filter = "SGBD File|*.prg";
            Nullable<bool> result = fileDialog.ShowDialog();
            if (result == true)
            {
                Global.ecuPath = System.IO.Path.GetDirectoryName(fileDialog.FileName);
                Global.sgbd = System.IO.Path.GetFileName(fileDialog.FileName);
            }

        }



        private void LoadFile_Click(object sender, RoutedEventArgs e)
        {
            UpdateProgressBar(0);
            LoadFile_1();
        }

        /*private void LoadFile2_Click(object sender, RoutedEventArgs e)
        {
            UpdateProgressBar(0);
            LoadFile_2();
        }*/

        private void FlashData_Click(object sender, RoutedEventArgs e)
        {
            FlashDME_Data();
        }

        private void FlashProgram_Click(object sender, RoutedEventArgs e)
        {
            Flashfull(false);
        }

        private void ReadTune_Click(object sender, RoutedEventArgs e)
        {
            ReadDME();
        }

        private void ReadFull_Click(object sender, RoutedEventArgs e)
        {
            ReadDME_Full();
        }

        private void Read_RAM_Click(object sender, RoutedEventArgs e)
        {
            //ReadRAM();
        }

        private bool CurrentlyFlashing = false;

        private bool FullbinLoaded = false;

        void MainWindow_Closing(object sender, CancelEventArgs e)
        {
            if (this.CurrentlyFlashing)
            {
                string msg = "Currently flashing DME, exiting now may have unpredictable results.\n\nAre you sure you want to exit?";
                MessageBoxResult result =
                  MessageBox.Show(
                    msg,
                    "Currently Flashing",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                if (result == MessageBoxResult.No)
                {
                    // If user doesn't want to close, cancel closure
                    e.Cancel = true;
                }
            }
        }


        private void IdentDME()
        {
            string DMEType;
            using (EdiabasNet ediabas = StartEdiabas())
            {


                ExecuteJob(ediabas, "aif_lesen", string.Empty);

                Global.VIN = GetResult_String("AIF_FG_NR", ediabas.ResultSets);

                ExecuteJob(ediabas, "hardware_referenz_lesen", string.Empty);

                Global.HW_Ref = GetResult_String("HARDWARE_REFERENZ", ediabas.ResultSets);

                ExecuteJob(ediabas, "daten_referenz_lesen", string.Empty);

                String SW_Ref = GetResult_String("DATEN_REFERENZ", ediabas.ResultSets);

                if (SW_Ref.Length > 12)
                    SW_Ref = SW_Ref.Substring(12);

                Global.SW_Ref = SW_Ref;

                ExecuteJob(ediabas, "zif_lesen", string.Empty);
                string zif = string.Empty;
                if (GetResult_String("ZIF_PROGRAMM_REFERENZ", ediabas.ResultSets).Contains(Global.HW_Ref))
                    zif = GetResult_String("ZIF_PROGRAMM_STAND", ediabas.ResultSets);
                else
                {
                    ExecuteJob(ediabas, "zif_backup_lesen", string.Empty);
                    if (GetResult_String("ZIF_BACKUP_PROGRAMM_REFERENZ", ediabas.ResultSets).Contains(Global.HW_Ref))
                        zif = GetResult_String("ZIF_BACKUP_PROGRAMM_STAND", ediabas.ResultSets);
                }

                Global.ZIF = zif;

                ExecuteJob(ediabas, "flash_programmier_status_lesen", string.Empty);

                string programming_status = GetResult_String("FLASH_PROGRAMMIER_STATUS_TEXT", ediabas.ResultSets);

                DMEType = "Unknown / Unsuppported";

                if (Global.HW_Ref == "0049R20")
                    DMEType = "MSS70";
                if (Global.HW_Ref == "0049PP0")
                    DMEType = "MSV70";            

                if (!ExecuteJob(ediabas, "DIAGNOSEPROTOKOLL_LESEN", string.Empty))
                {
                    return;
                }

                Global.diagProtocol = GetResult_String("DIAG_PROT_IST", ediabas.ResultSets);
                this.Dispatcher.Invoke(() =>
                {
                    DMEType_Box.Content = DMEType;
                    HWRef_Box.Content = Global.HW_Ref;
                    ZIF_Box.Content = Global.ZIF;
                    SWRef_Box.Content = Global.SW_Ref;
                    programStatus_Box.Content = programming_status;
                    VIN_Box.Content = Global.VIN;
                    //diagProtocol_Box.Content = Global.diagProtocol;

                    if (DMEType != String.Empty && DMEType != "Unknown / Unsuppported")
                    {
                        LoadFile.IsEnabled = true;
                        ReadTune.IsEnabled = true;
                        ReadFull.IsEnabled = true;
                    }
                });
            }
        }

        private void LoadFile_1()
        {
            OpenFileDialog openFile = new OpenFileDialog();
            openFile.InitialDirectory = System.IO.Path.GetDirectoryName(System.AppDomain.CurrentDomain.BaseDirectory);
            openFile.Filter = "Binary|*.bin|Original File|*.ori|All Files|*.*";
            Nullable<bool> result = openFile.ShowDialog();
            if (result == true)
            {
                Global.openedFlash = null;
                Global.openedFlash = File.ReadAllBytes(openFile.FileName);

                if (Global.openedFlash.Length == 0x20000 || Global.openedFlash.Length == 0x1EB00)
                {
                    if (!VerifyParameterMatch(Global.openedFlash, Global.HW_Ref, Global.ZIF))
                    {
                        Global.openedFlash = null;
                        FlashDME.IsEnabled = false;
                        FlashProgram.IsEnabled = false;
                        statusTextBlock.Text = "Tune does not match program";
                        return;
                    }

                    else
                    {
                        FlashDME.IsEnabled = true;
                        FlashProgram.IsEnabled = false;
                    }
                }

                if (Global.openedFlash.Length == 0x200000)
                {
                    if (!VerifyProgramMatch(Global.openedFlash.Take(0x180000).ToArray(), Global.HW_Ref))
                    {
                        Global.openedFlash = null;
                        FlashDME.IsEnabled = false;
                        FlashProgram.IsEnabled = false;
                        statusTextBlock.Text = "Program does not match hardware";
                        return;
                    }
                    if (VerifyParameterMatch(Global.openedFlash.Skip(0x40000).Take(0x20000).ToArray(), Global.HW_Ref, Global.ZIF))
                        FlashDME.IsEnabled = true;

                    if (!VerifyFlashMPCMatch(Global.openedFlash.Take(0x180000).ToArray(), Global.openedFlash.Skip(0x180000).Take(0x80000).ToArray()))
                    {
                            Global.openedFlash = null;
                            Global.openedMPC = null;
                            FlashDME.IsEnabled = false;
                            FlashProgram.IsEnabled = false;
                            statusTextBlock.Text = "Program does not match hardware";
                    }
                    
                    FlashDME.IsEnabled = true;
                    FlashProgram.IsEnabled = true;
                    AdvancedMenu.IsEnabled = true;
                    RSA_Bypass_Fast.IsEnabled = true;
                }              
            }

            else
            {
                FlashDME.IsEnabled = false;
                Global.openedFlash = null;
            }

            if (Global.openedFlash != null)
            {
                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Loaded " + Path.GetFileName(openFile.FileName);
                });
            }
        }

        /*private void LoadFile_2()
        {
            OpenFileDialog openFile = new OpenFileDialog();
            openFile.InitialDirectory = System.IO.Path.GetDirectoryName(System.AppDomain.CurrentDomain.BaseDirectory);
            openFile.Filter = "Binary|*.bin|Original File|*.ori|All Files|*.*";
            Nullable<bool> result = openFile.ShowDialog();
            if (result == true)
            {
                Global.openedMPC = File.ReadAllBytes(openFile.FileName);
            }
            if (Global.openedMPC.Length != 0x80000)
            {
                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Invalid mpc file length";
                });

                FlashProgram.IsEnabled = false;
                Global.openedMPC = null;
            }


            if (Global.openedMPC != null)
            {
                if (Global.openedFlash != null)
                {
                    if (!VerifyFlashMPCMatch(Global.openedFlash, Global.openedMPC))
                    {
                            Global.openedFlash = null;
                            Global.openedMPC = null;
                            FlashDME.IsEnabled = false;
                            FlashProgram.IsEnabled = false;
                            return;
                    }

                    FlashDME.IsEnabled = true;
                    FlashProgram.IsEnabled = true;
                }
                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Loaded " + Path.GetFileName(openFile.FileName);
                });
            }
        }*/

        private bool VerifyParameterMatch(byte[] flash, string hwref, string zif)
        {
            bool match = false;

            string binref = System.Text.Encoding.ASCII.GetString(flash.Skip(0x10).Take(0xC).ToArray());


            if (!(hwref == null))
            {
                if (binref.Contains(hwref) && binref.Contains(zif))
                    match = true;
            }

            return match;
        }

        private bool VerifyProgramMatch(byte[] flash, string hwref)
        {
            bool match = false;

            string binref = System.Text.Encoding.ASCII.GetString(flash.Skip(0x80724).Take(0xC).ToArray());

            if (binref.Contains(hwref))
                match = true;

            return match;
        }

        private bool VerifyFlashMPCMatch(byte[] flash, byte[] mpc)
        {
            bool match = false;

            string flashstring = System.Text.Encoding.ASCII.GetString(flash.Skip(0x80714).Take(0xA).ToArray());
            string mpcstring = System.Text.Encoding.ASCII.GetString(mpc.Skip(0x7FFC0).Take(0xA).ToArray());

            if (Convert.ToUInt64(flashstring) - Convert.ToUInt64(mpcstring) == 500)
                match = true;

            return match;
        }

        private void UpdateProgressBar(uint progress)
        {
            ProgressDME.Dispatcher.Invoke(() => ProgressDME.Value = progress, System.Windows.Threading.DispatcherPriority.Background);
        }

        private void ProgressDME_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {

        }

        private void worker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            ProgressDME.Value = Math.Min(e.ProgressPercentage, 100);
        }




        //Read, Write, Erase
        private async void ReadDME()

        {

            uint start = 0;
            uint end = 0;
            string MemSegment = string.Empty;
            byte[] MemoryDump = null;


            using (EdiabasNet ediabas = StartEdiabas())
            {

                if (Global.diagProtocol != "BMW-FAST")
                {
                    await Task.Run(() =>
                    {
                        if (!RequestSecurityAccess(ediabas))
                        {
                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Security Access Denied";
                            });
                        }
                    });

                }
  

                start = 0x40000;
                end = 0x5FFFF;
                MemSegment = "LAR";

                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Reading parameters";
                });
                await Task.Run(() => MemoryDump = ReadMemory(ediabas, start, end, MemSegment));


                    this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = null;
                });
                SaveFileDialog saveFile = new SaveFileDialog();


                saveFile.FileName = Global.VIN + "_" + Global.ZIF + "_" + Global.SW_Ref; 

                saveFile.InitialDirectory = System.IO.Path.GetDirectoryName(System.AppDomain.CurrentDomain.BaseDirectory);
                saveFile.Filter = "Binary|*.bin|Original File|*.ori|All Files|*.*";
                try
                {
                    Nullable<bool> result = saveFile.ShowDialog();
                    if (result == true)
                        File.WriteAllBytes(saveFile.FileName, MemoryDump);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception caught in process: {0}", ex);
                    MessageBox.Show("Error trying to save file");
                }

                MemoryDump = null;

                if (Global.diagProtocol != "BMW-FAST")
                {
                    if (!ExecuteJob(ediabas, "diagnose_mode", "DEFAULT;PC9600"))
                    {
                        return;
                    }
                    if (!ExecuteJob(ediabas, "SET_PARAMETER", ";9600"))
                    {
                        return;
                    }
                }

                MemoryDump = null;
            }
        } 

        private async void ReadDME_Full()
        {
            uint start = 0;
            uint end = 0;
            string MemSegment = string.Empty;
            byte[] MemoryDump = null;
            byte[] mpcdump = null;
      

            start = 0x00000;
            end = 0x17FFFF;
            MemSegment = "LAR";

            using (EdiabasNet ediabas = StartEdiabas())
            {

                if (Global.diagProtocol != "BMW-FAST")
                {
                    await Task.Run(() =>
                    {
                        if (!RequestSecurityAccess(ediabas))
                        {
                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Security Access Denied";
                            });
                        }
                    });

                }


                this.Dispatcher.Invoke(() =>
            {
                statusTextBlock.Text = "Reading External Flash";
            });
                await Task.Run(() => MemoryDump = ReadMemory(ediabas, start, end, MemSegment));

                start = 0x00000;
                end = 0x7FFFF;
                MemSegment = "FLASH";
                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Reading Internal Flash";
                });
                await Task.Run(() => mpcdump = ReadMemory(ediabas, start, end, MemSegment));

                byte[] fullbin = MemoryDump.Concat(mpcdump).ToArray();

                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = null;
                });
                SaveFileDialog saveFile = new SaveFileDialog();

                saveFile.FileName = Global.VIN + "_" + Global.ZIF + "_Full";
            
                saveFile.InitialDirectory = System.IO.Path.GetDirectoryName(System.AppDomain.CurrentDomain.BaseDirectory);
                saveFile.Filter = "Binary|*.bin|Original File|*.ori|All Files|*.*";
                try
                {
                    Nullable<bool> result = saveFile.ShowDialog();
                    if (result == true)
                        File.WriteAllBytes(saveFile.FileName, fullbin);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception caught in process: {0}", ex);
                    MessageBox.Show("Error trying to save file");
                }

                if (Global.diagProtocol != "BMW-FAST")
                {
                    if (!ExecuteJob(ediabas, "diagnose_mode", "DEFAULT;PC9600"))
                    {
                        return;
                    }
                    if (!ExecuteJob(ediabas, "SET_PARAMETER", ";9600"))
                    {
                        return;
                    }
                   
                }
                MemoryDump = null;
                mpcdump = null;
            }
        }

        //Consider adding RAM reading
        
        private byte[] ReadMemory(EdiabasNet ediabas, uint start, uint end, string MemSegment)
        {
            SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS | EXECUTION_STATE.ES_SYSTEM_REQUIRED | EXECUTION_STATE.ES_AWAYMODE_REQUIRED);

            byte[] MemoryDump = { };
            byte[] MemoryRead = { };
            byte[] Result = { };
            uint length = end - start + 1;
            uint lengthRemaining = length;
            uint segLength = 254;
            uint bytesRead = 0;

            while (bytesRead < length)
            {
                if (lengthRemaining < segLength)
                    segLength = lengthRemaining;
                if (!ExecuteJob(ediabas, "speicher_lesen_ascii", MemSegment + ";" + start + ";" + segLength))
                {
                    SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
                    return MemoryDump;
                }

                bytesRead += segLength;
                MemoryRead = GetResult_ByteArray("DATEN", ediabas.ResultSets);

                start = start + segLength;
                lengthRemaining = lengthRemaining - segLength;

                uint progress = bytesRead * 500 / length;
                UpdateProgressBar(progress);
                MemoryDump = MemoryDump.Concat(MemoryRead).ToArray();
            }

            //Console.WriteLine("Out of loop");
            //Console.WriteLine(bytesRead.ToString("X"));
            //Console.WriteLine(segLength.ToString("X"));
            SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
            return MemoryDump;
        }

        private async Task FlashDME_Data()
        {
            Checksums_Signatures ChecksumsSignatures = new Checksums_Signatures();
            {
                bool success = true;
                using (EdiabasNet ediabas = StartEdiabas())
                {

                    await Task.Run(() =>
                    {
                        if (!RequestSecurityAccess(ediabas))
                        {
                            success = false;
                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Security Access Denied";
                            });
                        }
                    });

                    uint eraseStart = 0x840000;
                    uint eraseBlock = 0x1EB00;
                    uint flashStart = 0x840000;
                    uint flashEnd = 0x85EAFF;


                    if (Global.diagProtocol == "BMW-FAST")
                    {
                        ExecuteJob(ediabas, "normaler_datenverkehr", "nein;nein;ja");
                        ExecuteJob(ediabas, "normaler_datenverkehr", "ja;nein;nein");
                    }

                    this.Dispatcher.Invoke(() =>
                    {
                        statusTextBlock.Text = "Erasing Flash";
                    });
                    await Task.Run(() => success = EraseECU(ediabas, eraseBlock, eraseStart));

                    byte[] toFlash = null;

                    if (Global.openedFlash.Length > 0x40000)
                        toFlash = Global.openedFlash.Skip(0x40000).Take(0x1EB00).ToArray();
                    else
                        toFlash = Global.openedFlash.Take(0x1EB00).ToArray();

                    toFlash = ChecksumsSignatures.CorrectParameterChecksums(toFlash);

                

                    this.Dispatcher.Invoke(() =>
                    {
                        statusTextBlock.Text = "Flashing ECU";
                    });
                    await Task.Run(() => success = FlashBlock(ediabas, toFlash, flashStart, flashEnd));

                    if (success)
                    {
                        await Task.Run(() =>
                        {
                            if (Global.diagProtocol != "BMW-FAST")
                            {
                                if (!ExecuteJob(ediabas, "diagnose_mode", "DEFAULT;PC9600"))
                                {
                                    success = false;
                                    return;
                                }
                                if (!ExecuteJob(ediabas, "SET_PARAMETER", ";9600"))
                                {
                                    success = false;
                                    return;
                                }
                            }
                            else
                            {
                                if (!ExecuteJob(ediabas, "diagnose_mode", "DEFAULT"))
                                {
                                    success = false;
                                    return;
                                }

                                if (!ExecuteJob(ediabas, "normaler_datenverkehr", "ja;nein;ja"))
                                {
                                    success = false;
                                    return;
                                }
                            }

                            if (!ExecuteJob(ediabas, "FLASH_PROGRAMMIER_STATUS_LESEN", String.Empty))
                            {
                                success = false;
                                return;
                            }

                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Checking signature";
                            });
                            if (!ExecuteJob(ediabas, "FLASH_SIGNATUR_PRUEFEN", "Daten;64"))
                            {
                                this.Dispatcher.Invoke(() =>
                                {
                                    statusTextBlock.Text = "Signature check failed";
                                });
                                success = false;

                                if (!ExecuteJob(ediabas, "STEUERGERAETE_RESET", String.Empty))
                                {
                                    return;
                                }
                                return;
                            }
                            if (!ExecuteJob(ediabas, "FLASH_PROGRAMMIER_STATUS_LESEN", String.Empty))
                            {
                                success = false;
                                return;
                            }
                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Resetting ECU";
                            });
                            if (!ExecuteJob(ediabas, "STEUERGERAETE_RESET", String.Empty))
                            {
                                return;
                            }
                        });

                        if (success)
                        {

                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Flash successful";
                            });

                        }
                        else
                        {
                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Flash failed";
                            });
                        }
                    }
                    //System.Threading.Thread.Sleep(2500);
                    IdentDME();
                    IdentDME();
                    return;
                }
            }
        }

        private async Task Flashfull(bool patchRSA)
        {
            Checksums_Signatures ChecksumsSignatures = new Checksums_Signatures();
            bool success = true;            

            using (EdiabasNet ediabas = StartEdiabas())
            {

                await Task.Run(() =>
                {
                    if (!RequestSecurityAccess(ediabas))
                    {
                        success = false;
                        this.Dispatcher.Invoke(() =>
                        {
                            statusTextBlock.Text = "Security Access Denied";
                        });
                    }
                });

                uint flashRSAPatch = 0x40000;
                uint flashRSAPatchEnd = 0x5FF7F;
                uint flashBoot = 0x60000;
                uint flashBootEnd = 0x7FF7F;

                uint flashProgram = 0x80100;
                uint flashProgramEnd = 0x17FFFF;

                uint flashMPCStart = 0x400000;
                uint flashMPCEnd = 0x47FFFF;

                if (Global.diagProtocol == "BMW-FAST")
                {
                    ExecuteJob(ediabas, "normaler_datenverkehr", "nein;nein;ja");
                    ExecuteJob(ediabas, "normaler_datenverkehr", "ja;nein;nein");
                }

                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Erasing Flash";
                });
                await Task.Run(() => success = EraseECU(ediabas, 0x10, 0x60000));
                if (patchRSA)
                    await Task.Run(() => success = EraseECU(ediabas, 0x10, 0x40000));

                byte[] toFlash = Global.openedFlash.Take(0x180000).ToArray();
                byte[] toFlashMPC = Global.openedFlash.Skip(0x180000).Take(0x80000).ToArray();
                toFlash = ChecksumsSignatures.PrepareProgram(toFlash, toFlashMPC, patchRSA);

                byte[] toFlashStockBoot = toFlash.Skip(0x20000).Take(0x1ff80).ToArray();
                byte[] toFlashBoot = toFlash.Skip(0x60000).Take(0x1FF80).ToArray();
                byte[] toFlashProgram = toFlash.Skip(0x80100).ToArray();

               

                if (patchRSA)
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        statusTextBlock.Text = "Flashing RSA Patch";
                    });
                    await Task.Run(() => success = FlashBlock(ediabas, toFlashStockBoot, flashRSAPatch, flashRSAPatchEnd));
                }

                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Flashing Boot";
                });
                await Task.Run(() => success = FlashBlock(ediabas, toFlashBoot, flashBoot, flashBootEnd));

                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Flashing External Program";
                });
                await Task.Run(() => success = FlashBlock(ediabas, toFlashProgram, flashProgram, flashProgramEnd));

                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Flashing Internal Program";
                });

                await Task.Run(() => success = FlashBlock(ediabas, toFlashMPC, flashMPCStart, flashMPCEnd));

                if (success)
                {
                    await Task.Run(() =>
                    {
                        if (Global.diagProtocol != "BMW-FAST")
                        {
                            if (!ExecuteJob(ediabas, "diagnose_mode", "DEFAULT;PC9600"))
                            {
                                success = false;
                                return;
                            }
                            if (!ExecuteJob(ediabas, "SET_PARAMETER", ";9600"))
                            {
                                success = false;
                                return;
                            }
                        }
                        else
                        {
                            if (!ExecuteJob(ediabas, "normaler_datenverkehr", "ja;nein;ja"))
                            {
                                success = false;
                                return;
                            }
                        }

                        if (!ExecuteJob(ediabas, "FLASH_PROGRAMMIER_STATUS_LESEN", String.Empty))
                        {
                            success = false;
                            return;
                        }

                        this.Dispatcher.Invoke(() =>
                        {
                            statusTextBlock.Text = "Checking signature";
                        });
                        if (!ExecuteJob(ediabas, "FLASH_SIGNATUR_PRUEFEN", "Programm;64"))
                        {
                            this.Dispatcher.Invoke(() =>
                            {
                                statusTextBlock.Text = "Signature check failed";
                            });
                            success = false;

                            if (!ExecuteJob(ediabas, "STEUERGERAETE_RESET", String.Empty))
                            {
                                return;
                            }
                            return;
                        }
                        if (!ExecuteJob(ediabas, "FLASH_PROGRAMMIER_STATUS_LESEN", String.Empty))
                        {
                            success = false;
                            return;
                        }
                        this.Dispatcher.Invoke(() =>
                        {
                            statusTextBlock.Text = "Resetting ECU";
                        });
                        if (!ExecuteJob(ediabas, "STEUERGERAETE_RESET", String.Empty))
                        {
                            return;
                        }
                    });

                    
                    if (success)
                    {

                        this.Dispatcher.Invoke(() =>
                        {
                            statusTextBlock.Text = "Flash successful";
                        });
                    }
                    else
                    {
                        this.Dispatcher.Invoke(() =>
                        {
                            statusTextBlock.Text = "Flash failed";
                        });
                    }
                    

                }
                //System.Threading.Thread.Sleep(2500);
                IdentDME();
                IdentDME();
                return;
            }
        }

        private bool FlashBlock(EdiabasNet ediabas, byte[] toFlash, uint blockStart, uint blockEnd)
        {
            SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS | EXECUTION_STATE.ES_SYSTEM_REQUIRED | EXECUTION_STATE.ES_AWAYMODE_REQUIRED); //Should prevent system from going idle while flashing

            uint blockStartOrig = blockStart;
            uint blockLength = blockEnd - blockStart + 1;

            byte[] flashAddressSet = new Byte[22];
            flashAddressSet[0] = 1;
            flashAddressSet[21] = 3;

            BitConverter.GetBytes(blockStart).CopyTo(flashAddressSet, 17);
            BitConverter.GetBytes(blockLength).CopyTo(flashAddressSet, 13);
            //See ediabas comments on flash_schreiben_adresse to see details on how this array should be set


            byte[] flashHeader = new Byte[21];
            byte[] three = { 3 };
            int flashSegLength = 0xFD;
            flashHeader[0] = 1;
            flashHeader[13] = (byte)flashSegLength;

            string flashAddressJob = "flash_schreiben_adresse";
            string flashJob = "flash_schreiben";
            string flashEndJob = "flash_schreiben_ende";
            
            if (!ExecuteJob(ediabas, flashAddressJob, flashAddressSet))
            {
                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Failed to set flash address";
                });
                SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
                return false;
            }

            while (blockLength > 0)
            {
                if (blockLength < flashSegLength)
                {
                    flashSegLength = (int)blockLength;
                    flashHeader[13] = (byte)flashSegLength;
                }
                BitConverter.GetBytes(blockStart).CopyTo(flashHeader, 17);

                if (!ExecuteJob(ediabas, flashJob, flashHeader.Concat(toFlash.Skip((int)(blockStart) - (int)blockStartOrig).Take(flashSegLength)).Concat(three).ToArray())) //See Ediabas comments for details on what the flash message should look like
                {
                    this.Dispatcher.Invoke(() =>
                    {
                        statusTextBlock.Text = "Flash failed at 0x" + blockStart.ToString("X") + ". Resetting DME.";
                    });
                    if (!ExecuteJob(ediabas, "STEUERGERAETE_RESET", String.Empty))
                    {
                        this.Dispatcher.Invoke(() =>
                        {
                            statusTextBlock.Text = "Error Resetting ECU";
                        });
                        SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
                        return false;
                    }
                    SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
                    return false;
                }
                blockStart += (uint)flashSegLength;
                blockLength -= (uint)flashSegLength;

                uint progress = (blockStart - blockStartOrig) * 500 / (blockEnd - blockStartOrig);
                UpdateProgressBar(progress);

            }
            if (!ExecuteJob(ediabas, flashEndJob, flashAddressSet))
            {
                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Failed to end flash job";
                });
                SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
                return false;
            }
            SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS); //Allow system to idle
            return true;
        }

        private bool EraseECU(EdiabasNet ediabas, uint blockLength, uint blockStart)
        {
            string flashEraseJob = "flash_loeschen";

            //byte[] eraseCommand = { 01, 01, 00, 00, 0xFE, 00, 00, 00, 00, 0xFF, 00, 00, 00, 0x44, 0xEA, 01, 00, 00, 00, 0x84, 00, 03 };
            byte[] eraseCommand = new Byte[22];
            eraseCommand[0] = 1;
            eraseCommand[4] = 0xFE;

            BitConverter.GetBytes(blockStart).CopyTo(eraseCommand, 17); //Start address
            BitConverter.GetBytes(blockLength).CopyTo(eraseCommand, 13); //Length - doesn't really matter for erases. 
                                                                         //Erasing something in the program space will erase the entire program space, erasing anything in the parameter space will erase entire parameter space)
            if (!ExecuteJob(ediabas, flashEraseJob, eraseCommand))
            {
                this.Dispatcher.Invoke(() =>
                {
                    statusTextBlock.Text = "Erase failed";
                });
                return false;
            }
            return true;
        }


        //Security Access
        private bool RequestSecurityAccess(EdiabasNet ediabas)
        {
            Checksums_Signatures ChecksumsSignatures = new Checksums_Signatures();

            this.Dispatcher.Invoke(() =>
            {
                statusTextBlock.Text = "Requesting Security Access";
            });
            if (!ExecuteJob(ediabas, "seriennummer_lesen", string.Empty))
                return false;
            byte[] serialReply = GetResult_ByteArray("_TEL_ANTWORT", ediabas.ResultSets);
            byte[] serialNumber = serialReply.Skip(serialReply.Length - 5).Take(4).ToArray(); //DME uses last 4 bytes of serial number in authentication message
            byte[] userID = new byte[4]; //user ID can be any 4 bytes. 
            Random rng = new Random();
            rng.NextBytes(userID); 

            if (!ExecuteJob(ediabas, "authentisierung_zufallszahl_lesen", "3;0x" + BitConverter.ToUInt32(userID.Reverse().ToArray(), 0).ToString("X")))//Request random number, passing the "userID" generated above as an argument
                return false;
            byte[] seed = GetResult_ByteArray("ZUFALLSZAHL", ediabas.ResultSets); //DME sends a random number


            if (!ExecuteJob(ediabas, "authentisierung_start", ChecksumsSignatures.GetSecurityAccessMessage(userID, serialNumber, seed))) //Sign message using level 3 private key. If DME decrypts successfully and it matches its own calculation, security access is granted
                return false;

            if (Global.diagProtocol != "BMW-FAST") //If not using the BMW-FAST protocol (BN2000 cars, i.e E6x/E9x), raise baudrate (from 9600 default) to 115200
            {
                if (!ExecuteJob(ediabas, "diagnose_mode", "ECUPM;PC115200")) //Request ECUProgramming mode @ baudrate 115200
                {
                    return false;
                }
                if (!ExecuteJob(ediabas, "SET_PARAMETER", ";115200")) //Sets serial port baudrate to 115200
                {                                                     
                    return false;
                }
                if (!ExecuteJob(ediabas, "ACCESS_TIMING_PARAMETER", "00;120;0;240;00")) //WinKFP does this -- not 100% sure of what it actually changes. If job is skipped, communications don't work
                                                                                         //If not set to what the specific module wants, the job doesn't execute. 
                {
                    return false;
                }

                if (!ExecuteJob(ediabas, "SET_PARAMETER", ";115200;;15"))
                {
                    return false;
                }

            }

            else //"BMW-FAST" cars communicate @ 115200 natively and don't need all those parameters set
            {
                if (!ExecuteJob(ediabas, "diagnose_mode", "ECUPM"))
                {
                    return false;
                }
            }
            return true;//Should be in ECU Programming Mode now

        }


        //The below is basically ripped straight out of example ediabaslib code
        private EdiabasNet StartEdiabas()
        {
            EdiabasNet ediabas = new EdiabasNet();
            EdInterfaceBase edInterface;
            edInterface = new EdInterfaceObd();


            ediabas.EdInterfaceClass = edInterface;
            ediabas.ProgressJobFunc = ProgressJobFunc;
            ediabas.ErrorRaisedFunc = ErrorRaisedFunc;

            ((EdInterfaceObd)edInterface).ComPort = Global.Port;

            ediabas.ArgBinary = null;
            ediabas.ArgBinaryStd = null;
            ediabas.ResultsRequests = string.Empty;

            ediabas.SetConfigProperty("EcuPath", Global.ecuPath);
            ediabas.ResultsRequests = string.Empty;

            try
            {
                ediabas.ResolveSgbdFile(Global.sgbd);
            }

            catch (Exception ex2)
            {
                System.Diagnostics.Debug.WriteLine("ResolveSgbdFile failed: " + EdiabasNet.GetExceptionText(ex2));
            }

            return ediabas;
        }

        private static void ProgressJobFunc(EdiabasNet ediabas)
        {
            string infoProgressText = ediabas.InfoProgressText;
            int infoProgressPercent = ediabas.InfoProgressPercent;
            string text = string.Empty;
            if (infoProgressPercent >= 0)
            {
                text += string.Format("{0,3}% ", infoProgressPercent);
            }
            if (infoProgressText.Length > 0)
            {
                text += string.Format("'{0}'", infoProgressText);
            }
            if (text.Length > 0)
            {
                System.Diagnostics.Debug.WriteLine("Progress: " + text);
            }
        }

        private static void ErrorRaisedFunc(EdiabasNet.ErrorCodes error)
        {
            string errorDescription = EdiabasNet.GetErrorDescription(error);
            System.Diagnostics.Debug.WriteLine("Error occured: 0x{0:X08} {1}", new object[]
            {
        (uint)error,
        errorDescription
            });
        }

        private static string GetResult_String(string resultName, List<Dictionary<string, EdiabasNet.ResultData>> resultSets)
        {
            string result = string.Empty;
            if (resultSets != null)
            {
                foreach (Dictionary<string, EdiabasNet.ResultData> dictionary in resultSets)
                {
                    foreach (string key in from x in dictionary.Keys
                                           orderby x
                                           select x)
                    {
                        EdiabasNet.ResultData resultData = dictionary[key];
                        if (resultData.Name == resultName && resultData.OpData is string)
                            result = (string)resultData.OpData;
                    }
                }
            }
            return result;
        }

        private static byte[] GetResult_ByteArray(string resultName, List<Dictionary<string, EdiabasNet.ResultData>> resultSets)
        {
            byte[] result = null;
            if (resultSets != null)
            {
                foreach (Dictionary<string, EdiabasNet.ResultData> dictionary in resultSets)
                {
                    foreach (string key in from x in dictionary.Keys
                                           orderby x
                                           select x)
                    {
                        EdiabasNet.ResultData resultData = dictionary[key];
                        if (resultData.Name == resultName && resultData.OpData.GetType() == typeof(byte[]))
                            result = (byte[])resultData.OpData;

                    }
                }
            }
            return result;
        }

        private static bool ExecuteJob(EdiabasNet ediabas, string Job, string Arg)
        {
            ediabas.ArgString = Arg;
            try
            {
                ediabas.ExecuteJob(Job);
            }
            catch (Exception ex)
            {
                if (ediabas.ErrorCodeLast == EdiabasNet.ErrorCodes.EDIABAS_ERR_NONE)
                {
                    System.Diagnostics.Debug.WriteLine("Job execution failed: " + EdiabasNet.GetExceptionText(ex));
                    System.Diagnostics.Debug.WriteLine("");

                }
                return false;
            }
            return (GetResult_String("JOB_STATUS", ediabas.ResultSets) == "OKAY");
        }

        private static bool ExecuteJob(EdiabasNet ediabas, string Job, byte[] Arg)
        {
            ediabas.ArgBinary = Arg;
            try
            {
                ediabas.ExecuteJob(Job);
            }
            catch (Exception ex)
            {
                if (ediabas.ErrorCodeLast == EdiabasNet.ErrorCodes.EDIABAS_ERR_NONE)
                {
                    System.Diagnostics.Debug.WriteLine("Job execution failed: " + EdiabasNet.GetExceptionText(ex));
                    System.Diagnostics.Debug.WriteLine("");
                }
                return false;
            }
            return (GetResult_String("JOB_STATUS", ediabas.ResultSets) == "OKAY");
        }
    }
}


