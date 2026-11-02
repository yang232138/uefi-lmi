# Original UFS entry serial log and dispatcher observer

Adds a bounded 32 KiB RAM copy at the source ShimLoader SerialPort Lib write
interface. The original serial write receives identical arguments exactly once
and its return value is preserved. Capture is enabled only around the original
target CoreStartImage; no extra entry, hardware or disk calls are made.
DXE Core discovers our named extension through the existing documented Shim HOB
and library loader, then publishes a separate configuration table for the viewer.
The viewer starts with log pages and then shows the existing dispatcher trace.
Overflow is counted, never overwrites earlier bytes. Empty logs are inconclusive.
This observer does not fix the UFS driver and does not qualify IOMMU/DMA or disks.
Original vendor UFSDxe bytes remain identical. No protocol or success is faked.

Diagnostic build only. The dispatcher retains its normal discovery, scheduling,
load and entry calls. Fixed-size DXE Core memory records only target GUID
0d35cd8e-97ea-4f9a-96af-0f0d89f76567, plus publication/dispatcher-end markers.
A configuration table publishes the record buffer; TraceView reads it before
ExitBootServices. No private memory scanning or persistent variables are used.

No additional StartImage, Dispatch, ConnectController, UFS/disk commands or MMIO
are introduced. The original firmware may still perform its normal hardware
initialization. Vendor binary bytes and board memory mappings are unchanged.
An entry-begin status of EFI_NOT_READY is a sentinel, not an entry failure.
The entry return record is the actual CoreStartImage return status. A successful
entry does not establish completion of callbacks, physical disks or DMA.

This rebuild is a new FD and must be qualified independently. Exact historical
FD identity no longer applies. Check the firmware and image hashes before one
temporary fastboot boot. Never flash this image. The payload contains only an
EFI result viewer, no XNU and no full OS. Android ADB will not be available in
the viewer. Photograph every result page; N/P and arrow keys navigate.

If the device fails before the viewer, the entry markers in the ordinary debug
output may help, but they do not guarantee an on-screen retained trace.
The collector reports dropped records instead of overwriting old evidence.
