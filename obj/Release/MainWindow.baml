   M S B A M L   `   `   `  ����   MyCourseWork    MyCourseWork.MainWindow   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml       � Title$  
MainWindow��$	��341��$	��525�� � 
ResizeMode$ NoResize=� � WindowStartupLocation$ CenterScreen=�.���  � RowDefinitions �� $��7* ��� $	��11* ��� $��2* �.+��� $��0��$��0��$	��3pxq����� .��Target file.���  � ColumnDefinitions �� $	��14* ��� $��1* � �� $
��25px ��� $
��25px �.+��� -    ��Name$ 
tbFilePath��$��0��$��0��$	��2pxq��� -    ��Name$ btnChooseFile��$��0��$��1��$	��2pxq�.��F� $��
2, 0, 0, 0q�$��18��$��15�� �� Stretch$
 Fill=�   FillPath#��[    folder_openStyle0#��[ �� $��1�� �� Orientation$ 
Horizontal=�$
��40px��.+�	� -   	 	�Name$	 	rbEncrypt��$	��5pxq�
 d� 	IsChecked$
 falseY�.���� -    ��Name$ contentLock��$ 
Horizontal=�$��	-5,-2,0,0q�.+�F� -    F�Name$ 
eyeEncrypt��$��16��$��16��$��
5, 0, 3, 0q�$
 Fill=�#��[    eye_closeStyle0#��[ �� $��	-7,-2,0,0q�.��	Encrypt	� -   $	 	rbDecrypt��$	��5pxq�$
 falseY�.���� -   $ contentUnlock��$ 
Horizontal=�$��	-5,-2,0,0q�.+�F� -   $ 
eyeDecrypt��$��16��$��16��$��
5, 0, 3, 0q�$
 Fill=�#��[    eye_checkStyle0#��[ �� $��	-7,-2,0,0q�.��	Decrypt�� $��1��$��0��$	��3pxq����� .��
Settings.���  �� $
��40px ��� $
��40px ��� $
��40px �.+��� $��0��$ Vertical=�.+��� $��0��$��10, -7, 0, -3q�.��	Password:G� -	    G�Name$ pbFirst��$��0��$��10, 0, 10, 0q��� $��1��$ Vertical=�.+��� $��0��$��10, -7, 0, -3q�.��Confirm Password:G� -
   $ pbSecond��$��0��$��10, 0, 10, 0q��� $��2��$ Vertical=�.+��� $��0��$��10, -7, 0, -3q�.��	Key File:�  �� $	��14* ��� $��1* �.+��� -   $ 	tbKeyPath��$��0��$��10, 0, 3, 0q�{�.  d� -    d�Name$ btnChooseKey��$��1��$��3, 0, 10, 0q�.��F� $��14��$��14�� �� Left$ 16��
 �� Top$ 12��$
 Fill=�#��[  #��[ �� $��2��$ 
Horizontal=�$��	208,0,0,0q�.+��� -    ��Name$ cbGenerateKey��$��10, 5, 0, 0q�$	��101��{��� *	IsChecked+ �� ElementName$ 	rbEncrypt��.��Generate Key�� -   $ 	btnAction��$��-2,1,0,3q�$
��75px��$
��26px��.���� $ 
Horizontal=�$��	-3,-2,0,0q�.+�F� -   $ actPath��$��23��$��23��$��
5, 1, 3, 0q��� -    ��Name$ actLabel��$��	-7,-2,0,0q��� -   $ cbErase��$��10, 5, 0, 0q�.��Erase Target File