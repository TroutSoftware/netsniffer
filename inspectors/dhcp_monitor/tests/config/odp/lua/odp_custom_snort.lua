---------------------------------------------------------------------------
-- Empty file
---------------------------------------------------------------------------

--[[
detection_name: cnn.com
version: 1
description: cnn.com wants a better description.
--]]

require "DetectorCommon"
local DC = DetectorCommon

local proto = DC.ipproto.tcp;
DetectorPackageInfo = {
	name = "cnn.com",
	proto = proto,
	server = {
		init = 'DetectorInit',
		clean = 'DetectorClean',
		minimum_matches = 1
	}
}

function DetectorInit(detectorInstance)

	gDetector = detectorInstance;
	gAppId = gDetector:open_createApp("cnn.com");

	if gDetector.addPortPatternService then
		gDetector:addPortPatternService(proto,80,"news",0, gAppId);
	end

	return gDetector;
end

function DetectorClean()
end

