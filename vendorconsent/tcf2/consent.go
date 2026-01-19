package vendorconsent

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/prebid/go-gdpr/api"
	"github.com/prebid/go-gdpr/bitutils"
	"github.com/prebid/go-gdpr/consentconstants"
)

const (
	consentStringTCF2Separator  = '.'
	consentStringTCF2Prefix     = 'C'
	segmentTypeDisclosedVendors = 1
)

// ParseString parses the TCF 2.0 vendor string base64 encoded
func ParseString(consent string) (api.VendorConsents, error) {
	if consent == "" {
		return nil, consentconstants.ErrEmptyDecodedConsent
	}

	coreEnd := strings.IndexByte(consent, consentStringTCF2Separator)
	if coreEnd == -1 {
		coreEnd = len(consent)
	}

	coreSegment := consent[:coreEnd]
	buff := []byte(coreSegment)
	decoded := buff
	n, err := base64.RawURLEncoding.Decode(decoded, buff)
	if err != nil {
		return nil, err
	}
	decoded = decoded[:n:n]

	metadata, err := Parse(decoded)
	if err != nil {
		return nil, err
	}

	consentMetadata, ok := metadata.(ConsentMetadata)
	if ok && coreEnd < len(consent) {
		segmentStart := coreEnd + 1
		for segmentStart < len(consent) {
			segmentEnd := strings.IndexByte(consent[segmentStart:], consentStringTCF2Separator)

			if segmentEnd == -1 {
				segmentEnd = len(consent)
			} else {
				segmentEnd += segmentStart
			}

			segmentStr := consent[segmentStart:segmentEnd]
			segmentBuff := []byte(segmentStr)
			segmentDecoded := segmentBuff
			segmentN, err := base64.RawURLEncoding.Decode(segmentDecoded, segmentBuff)
			if err != nil {
				segmentStart = segmentEnd + 1
				continue
			}
			segmentDecoded = segmentDecoded[:segmentN]

			if len(segmentDecoded) == 0 {
				segmentStart = segmentEnd + 1
				continue
			}

			segmentType, err := bitutils.ParseByte3(segmentDecoded, 0)
			if err != nil {
				segmentStart = segmentEnd + 1
				continue
			}

			if segmentType == segmentTypeDisclosedVendors {
				oobDisclosedVendors, err := parseOOBVendorSegment(segmentDecoded, 3)
				if err == nil {
					consentMetadata.oobDisclosedVendors = oobDisclosedVendors
					break
				}
			}

			segmentStart = segmentEnd + 1
		}
		return consentMetadata, nil
	}
	return metadata, nil
}

// Parse parses the TCF 2.0 vendor consent data from the string. This string should *not* be encoded (by base64 or any other encoding).
// If the data is malformed and cannot be interpreted as a vendor consent string, this will return an error.
func Parse(data []byte) (api.VendorConsents, error) {
	metadata, err := parseMetadata(data)
	if err != nil {
		return nil, err
	}

	var vendorConsents vendorConsentsResolver
	var vendorLegitInts vendorConsentsResolver

	var legitIntStart uint
	var pubRestrictsStart uint
	// Bit 229 determines whether or not the consent string encodes Vendor data in a RangeSection or BitField.
	// We know from parseMetadata that we have at least 29*8=232 bits available
	if isSet(data, 229) {
		vendorConsents, legitIntStart, err = parseRangeSection(metadata, metadata.MaxVendorID(), 230)
	} else {
		vendorConsents, legitIntStart, err = parseBitField(metadata, metadata.MaxVendorID(), 230)
	}
	if err != nil {
		return nil, err
	}

	metadata.vendorConsents = vendorConsents
	metadata.vendorLegitimateInterestStart = legitIntStart + 17
	legIntMaxVend, err := bitutils.ParseUInt16(data, legitIntStart)
	if err != nil {
		return nil, err
	}

	if legitIntStart+16 >= uint(len(data))*8 {
		return nil, fmt.Errorf("invalid consent data: no legitimate interest start position")
	}
	if isSet(data, legitIntStart+16) {
		vendorLegitInts, pubRestrictsStart, err = parseRangeSection(metadata, legIntMaxVend, metadata.vendorLegitimateInterestStart)
	} else {
		vendorLegitInts, pubRestrictsStart, err = parseBitField(metadata, legIntMaxVend, metadata.vendorLegitimateInterestStart)
	}
	if err != nil {
		return nil, err
	}

	metadata.vendorLegitimateInterests = vendorLegitInts
	metadata.pubRestrictionsStart = pubRestrictsStart

	pubRestrictions, _, err := parsePubRestriction(metadata, pubRestrictsStart)
	if err != nil {
		return nil, err
	}

	metadata.publisherRestrictions = pubRestrictions

	return metadata, err

}

func parseOOBVendorSegment(segmentData []byte, startBit uint) (vendorConsentsResolver, error) {
	if len(segmentData)*8 < int(startBit)+16 {
		return nil, fmt.Errorf("OOB vendor segment too short")
	}

	maxVendorID, err := bitutils.ParseUInt16(segmentData, startBit)
	if err != nil {
		return nil, err
	}

	if maxVendorID == 0 {
		return nil, nil
	}

	encodingBit := startBit + 16
	if encodingBit >= uint(len(segmentData))*8 {
		return nil, fmt.Errorf("OOB vendor segment too short for encoding bit")
	}

	tempMetadata := ConsentMetadata{data: segmentData}
	if isSet(segmentData, encodingBit) {
		resolver, _, err := parseRangeSection(tempMetadata, maxVendorID, encodingBit+1)
		return resolver, err
	}
	resolver, _, err := parseBitField(tempMetadata, maxVendorID, encodingBit+1)
	return resolver, err
}

// IsConsentV2 return true if the consent strings looks like a tcf v2 consent string
func IsConsentV2(consent string) bool {
	return len(consent) > 0 && consent[0] == consentStringTCF2Prefix
}
