Plugin Purpose:

The EDFM Uploader plugin allows Elite Dangerous commanders using EDMC to automatically send valuable in-game data to the EDFM (Elite Dangerous Fleet Manager) platform. This includes:

Colonisation construction contributions
Live commander status (location, ship, credits, cargo)
Station market data
🚀 New & Improved:

Enhanced Logging: This version introduces more detailed and comprehensive logging throughout the plugin's operations. This will aid significantly in troubleshooting and understanding data flow. Log entries now include more context for sent events, API responses, and potential issues.
Debug Log Utility: The settings panel now includes a "Save Debug Log" button, which compiles relevant plugin settings along with the main EDMC log into a single file for easier support.
Key Features:

Seamless Data Upload: Automatically sends your construction material contributions, commander status updates, and market data to your faction's instance on edfm.space.
User Configuration:
Securely store your EDFM API key.
Choose which data types you want to contribute (Construction, Commander Status, Market Data).
Asynchronous & Robust Sending: Utilizes a background worker thread for non-blocking data transmission with built-in retries for network resilience.
Data Efficiency: Avoids sending redundant market and cargo data by comparing it with the last successfully sent information.
Helpful Links: Quick access to EDFM GalNet, active constructions, and API key management directly from the plugin settings.






Installation:

Download the load.py file.
Open EDMC.
Go to File -> Settings -> Plugins.
Click "Open" to navigate to your plugins directory.
Place the EDFM Uploader Folder into this directory.
Restart EDMC.
Configure your API key and preferences in the "EDFM Uploader" tab in EDMC settings.
Thank you for contributing to your faction's efforts with the EDFM Uploader!
