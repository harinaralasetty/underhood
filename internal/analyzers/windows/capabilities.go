package windows

import "github.com/harinaralasetty/underhood/internal/model"

type capabilityRule struct {
	severity model.Severity
	meaning  string
}

// capabilityRules is the single severity/meaning table for manifest capabilities.
// Unknown names remain informational, including unknown restricted declarations.
var capabilityRules = map[string]capabilityRule{
	"internetClient":             {model.Notable, "Requests outbound internet access."},
	"internetClientServer":       {model.Notable, "Requests inbound and outbound internet access."},
	"privateNetworkClientServer": {model.Notable, "Requests local-network client and server access."},
	"documentsLibrary":           {model.Notable, "Requests access to the documents library."},
	"picturesLibrary":            {model.Notable, "Requests access to the pictures library."},
	"videosLibrary":              {model.Notable, "Requests access to the videos library."},
	"musicLibrary":               {model.Notable, "Requests access to the music library."},
	"contacts":                   {model.Notable, "Requests access to contacts."},
	"appointments":               {model.Notable, "Requests access to appointments."},
	"removableStorage":           {model.Notable, "Requests access to removable storage."},
	"enterpriseAuthentication":   {model.Notable, "Requests use of enterprise credentials."},
	"sharedUserCertificates":     {model.Notable, "Requests access to shared user certificates."},
	"microphone":                 {model.Notable, "Requests microphone access."},
	"webcam":                     {model.Notable, "Requests camera access."},
	"location":                   {model.Notable, "Requests location access."},
	"bluetooth":                  {model.Notable, "Requests Bluetooth access."},
	"usb":                        {model.Notable, "Requests USB device access."},
	"serialcommunication":        {model.Notable, "Requests serial-device access."},
	"humaninterfacedevice":       {model.Notable, "Requests human-interface device access."},
	"radios":                     {model.Notable, "Requests control of device radios."},
	"runFullTrust":               {model.Sensitive, "Runs outside the app sandbox with the user's full privileges."},
	"broadFileSystemAccess":      {model.Sensitive, "Requests broad access to files available to the user."},
	"allowElevation":             {model.Sensitive, "Allows an application to request elevated privileges."},
	"packagedServices":           {model.Sensitive, "Declares support for packaged services."},
	"localSystemServices":        {model.Sensitive, "Declares support for services running as LocalSystem."},
	"unvirtualizedResources":     {model.Sensitive, "Requests access to resources without package virtualization."},
	"appDiagnostics":             {model.Sensitive, "Requests diagnostic information about other apps."},
	"packageManagement":          {model.Sensitive, "Requests management of installed app packages."},
	"confirmAppClose":            {model.Sensitive, "Requests the ability to delay app closure for confirmation."},
	"inputObservation":           {model.Sensitive, "Requests observation of user input."},
	"customInstallActions":       {model.Sensitive, "Declares custom package installation actions."},
}
