# web105

Hello, world.
Imports System.Net
Imports System.Net.Mail
Imports System.Net.NetworkInformation
Imports System.Net.Sockets
Imports System.Text
Imports System.Threading
Imports EzSmb


'Imports SharpCifs.Std
'Imports SharpCifs.Dcerpc
'Imports SharpCifs.Smb
'Imports SmbAbstraction
''Imports System.Net.NameResolution
'Imports System.Security.Cryptography.Algorithms
'Imports System.Security.Cryptography.Primitives
'Imports System.Threading.Tasks

Public Class Form1

    Private stopScanning As Boolean = False
    Private Function EnumerateSMBShares(ip As IPAddress) As List(Of String)
        Dim shares As New List(Of String)()

        Try
            ' Connect to the server on port 445
            Dim tcpClient As New TcpClient()
            tcpClient.Connect(ip, 445)

            Using networkStream As NetworkStream = tcpClient.GetStream()
                ' Send the SMB_COM_NEGOTIATE command to the server
                Dim negotiateCommand As Byte() = {
                    &HFF, &H53, &H4D, &H42, ' Protocol
                    &H72, ' Command: SMB_COM_NEGOTIATE
                    &H0, &H0, &H0, &H0, &H0, &H18, &H53, &HC8, ' Process ID, multiplex ID
                    &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
                    &H0, &H0, &H0, &H0
                }
                networkStream.Write(negotiateCommand, 0, negotiateCommand.Length)

                ' Receive the response from the server
                Dim buffer As Byte() = New Byte(255) {}
                txtResults.AppendText(buffer.ToString)
                Dim responseLength As Integer = networkStream.Read(buffer, 0, buffer.Length)
                WriteToTextBox(ip.ToString() & responseLength)
                ' Parse the response to determine if the server supports SMB
                If responseLength >= 36 AndAlso
                    buffer(9) = &H72 AndAlso
                    buffer(34) = &H80 AndAlso
                    buffer(35) = &H0 Then
                    ' The server supports SMB

                    ' Send the SMV the server
                    Dim treeConnectCommand As Byte() = {
                        &HFF, &H53, &H4D, &H42, ' Protocol
                        &H73, ' Command: SMB_COM_TREE_CONNECT_ANDX
                        &H0, &H0, &H0, &H0, &H0, &H18, &H53, &HC8, ' Process ID, multiplex ID
                        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
                        &H0, &H0, &H0, &H0, &HFF, &HFF, &H0, &H0,
                        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
                        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
                        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
                        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0
                    }
                    networkStream.Write(treeConnectCommand, 0, treeConnectCommand.Length)

                    ' Receive the response from the server
                    responseLength = networkStream.Read(buffer, 0, buffer.Length)
                    ' Parse the response to determine if the server supports SMB shares
                    If responseLength >= 9 AndAlso
    buffer(8) = &HFF Then
                        ' The server supports SMB shares

                        ' Send the SMB_COM_TRANSACTION2 command to the server
                        Dim transaction2Command As Byte() = {
        &HFF, &H53, &H4D, &H42, ' Protocol
        &H25, ' Command: SMB_COM_TRANSACTION2
        &H0, &H0, &H0, &H0, &H0, &H18, &H53, &HC8, ' Process ID, multiplex ID
        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
        &H0, &H10, &H0, &H0, &H0, &H1, &H0, &H0,
        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
        &H40, &H0, &H0, &H0, &H1, &H0, &H0, &H0,
        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
        &H0, &H0, &H0, &H0, &H0, &H0, &H0, &H0,
        &H0, &H0, &H0, &H0, &H0, &H0, &H0
    }
                        networkStream.Write(transaction2Command, 0, transaction2Command.Length)

                        ' Receive the response from the server
                        responseLength = networkStream.Read(buffer, 0, buffer.Length)

                        ' Parse the response to extract the list of SMB shares
                        If responseLength >= 9 AndAlso
        buffer(8) = &H0 Then
                            ' The response includes a list of SMB shares

                            ' The offset of the share names in the response
                            Dim offset As Integer = 61

                            ' Iterate over the share names
                            While offset < responseLength
                                ' The length of the share name
                                Dim nameLength As Integer = BitConverter.ToUInt16(buffer, offset)

                                ' The share name
                                Dim name As String = Encoding.Unicode.GetString(buffer, offset + 2, nameLength)

                                ' Add the share name to the list of shares
                                shares.Add(name)
                                WriteToTextBox(ip.ToString() & name)
                                ' Move the offset to the next share name
                                offset += 2 + nameLength
                            End While
                        End If
                    End If
                End If
            End Using
            Return shares
        Catch ex As Exception
        End Try
        Return shares
    End Function
    Private Async Sub btnStart_Click(sender As Object, e As EventArgs) Handles btnStart.Click

        stopScanning = False
        Dim startIP As IPAddress = IPAddress.Parse(TextBox1.Text)
        Dim endIP As IPAddress = IPAddress.Parse(TextBox2.Text)
        Dim range As New List(Of IPAddress)()

        For Each ip As IPAddress In GetIPRange(startIP, endIP)
            range.Add(ip)
        Next

        Dim progress As Integer = 0
        ProgressBar.Maximum = range.Count
        ProgressBar.Value = 0

        ' Use the Parallel.ForEach method to run the scanning tasks in parallel
        Await Task.Run(Sub() Parallel.ForEach(range,
        Async Sub(ip)
            If stopScanning Then
                Exit Sub
            End If
            If Pings(ip) Then
                Try
                    Dim remoteHost As IPHostEntry = Dns.GetHostEntry(ip)

                    Dim netbiosName As String = remoteHost.HostName
                    Dim hostName As String = remoteHost.HostName
                    WriteToTextBox(ip.ToString() & "online")
                    WriteToDataGridView(ip.ToString, netbiosName, ":Online", "0")
                Catch ex As Exception
                End Try
                If Await ScanPort(ip, 137) Then
                    WriteToTextBox(ip.ToString() & ":137")
                    WriteToDataGridView(ip.ToString(), "", ":Online", "137")
                    Dim shares As List(Of String) = EnumerateSMBShares(ip)
                End If
                If Await ScanPort(ip, 138) Then
                    WriteToTextBox(ip.ToString() & ":138")
                    WriteToDataGridView(ip.ToString(), "", "Online", "138")
                    Dim shares As List(Of String) = EnumerateSMBShares(ip)
                End If
                If Await ScanPort(ip, 139) Then
                    WriteToTextBox(ip.ToString() & ":139")
                    WriteToDataGridView(ip.ToString(), "", "Online", "139")
                    Dim shares As List(Of String) = EnumerateSMBShares(ip)
                End If
                If Await ScanPort(ip, 445) Then
                    WriteToTextBox(ip.ToString() & ":445")
                    WriteToDataGridView(ip.ToString(), "", "Online", "445")
                    Dim shares As List(Of String) = EnumerateSMBShares(ip)
                End If
                If Await ScanPort(ip, 80) Then
                    WriteToTextBox(ip.ToString() & ":80")
                    WriteToDataGridView(ip.ToString(), "80", "Online", "80")
                    Dim shares As List(Of String) = EnumerateSMBShares(ip)
                End If
            End If
            progress += 1
            UpdateProgressBar(progress)
        End Sub))



        '
    End Sub


    Private Function Pings(ip As IPAddress) As Boolean
        Dim ping As New Ping() ' Create a single Ping object that can be reused

        Try
            Dim reply As PingReply = ping.SendPingAsync(ip).Result ' Use SendAsync to send the ping asynchronously



            ' Use the NetBIOS name and host name as needed
            ToolStripLabel2.Text = (ip.ToString)




            Return (reply.Status = IPStatus.Success)
            ping.Dispose()
        Catch ex As Exception
            Return False
        End Try
    End Function

    Private Async Function ScanPort(ip As IPAddress, port As Integer) As Task(Of Boolean)
        Try
            Dim client As New TcpClient()
            Await client.ConnectAsync(ip, port)
            ToolStripLabel1.Text = (ip.ToString + port.ToString)
            Return True
        Catch ex As Exception
            Return False
        End Try
    End Function

    Private Sub btnStop_Click(sender As Object, e As EventArgs) Handles btnStop.Click
        stopScanning = True

    End Sub
    Function GetIPRange(startIP As IPAddress, endIP As IPAddress) As IEnumerable(Of IPAddress)
        Dim result As New List(Of IPAddress)()

        ' Convert the start and end IP addresses to strings
        Dim start As String = startIP.ToString()
        Dim [end] As String = endIP.ToString()

        ' Split the start and end IP addresses into their component parts
        Dim startParts As String() = start.Split(".")
        Dim endParts As String() = [end].Split(".")

        ' Convert the component parts to integers
        Dim startA As Integer = Integer.Parse(startParts(0))
        Dim startB As Integer = Integer.Parse(startParts(1))
        Dim startC As Integer = Integer.Parse(startParts(2))
        Dim startD As Integer = Integer.Parse(startParts(3))
        Dim endA As Integer = Integer.Parse(endParts(0))
        Dim endB As Integer = Integer.Parse(endParts(1))
        Dim endC As Integer = Integer.Parse(endParts(2))
        Dim endD As Integer = Integer.Parse(endParts(3))

        ' Iterate over the IP address range
        For a = startA To endA
            For b = startB To endB
                For c = startC To endC
                    For d = startD To endD
                        Dim ip As String = a & "." & b & "." & c & "." & d
                        result.Add(IPAddress.Parse(ip))
                    Next
                Next
            Next
        Next

        Return result
    End Function









    Private Sub WriteToDataGridView(ip As String, HOSTNAME As String, shareName As String, port As Integer)
        If DataGridView2.InvokeRequired Then
            DataGridView2.Invoke(
        Sub()
            ' Check if the row exists in the DataGridView
            If DataGridView2.Rows.Count > 0 Then
                ' Check if the cell exists in the DataGridView
                If DataGridView2.Columns.Contains("IPA") Then
                    ' Set the values for the cells in the row
                    DataGridView2.Rows.Insert(0, "IPA")
                    DataGridView2.Rows(0).Cells("IPA").Value = ip
                    DataGridView2.Rows(0).Cells("PORT").Value = port
                    DataGridView2.Rows(0).Cells("SHARE").Value = shareName
                    DataGridView2.Rows(0).Cells("HOSTNAME").Value = HOSTNAME
                    DataGridView2.Rows(0).Cells("HOSTNAME").Value = HOSTNAME
                End If
            End If
        End Sub
    )
        Else
            ' Check if the row exists in the DataGridView
            If DataGridView2.Rows.Count > 0 Then
                ' Check if the cell exists in the DataGridView
                If DataGridView2.Columns.Contains("IPA") Then
                    ' Set the values for the cells in the row
                    DataGridView2.Rows.Insert(0, "IPA")
                    DataGridView2.Rows(0).Cells("IPA").Value = ip
                    DataGridView2.Rows(0).Cells("PORT").Value = port
                    DataGridView2.Rows(0).Cells("SHARE").Value = shareName
                End If
            End If
        End If
    End Sub

    Private Sub WriteToTextBox(text As String)
        If txtResults.InvokeRequired Then
            txtResults.Invoke(
                Sub()
                    txtResults.AppendText(text & Environment.NewLine)
                End Sub
            )
        Else
            txtResults.AppendText(text & Environment.NewLine)
        End If
    End Sub

    Private Sub UpdateProgressBar(progress As Integer)
        If ProgressBar.InvokeRequired Then
            ProgressBar.Invoke(
                Sub()
                    ProgressBar.Value = progress
                End Sub
            )
        Else
            ProgressBar.Value = progress
        End If
    End Sub


    Private Sub Form1_Load(sender As Object, e As EventArgs) Handles MyBase.Load

    End Sub

    Private Sub DataGridView2_CellContentClick(sender As Object, e As DataGridViewCellEventArgs) Handles DataGridView2.CellContentClick

    End Sub
End Class

