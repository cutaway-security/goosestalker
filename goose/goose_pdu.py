# coding: utf-8

from pyasn1.codec.ber import encoder
from pyasn1.type import char, constraint, namedtype, tag, univ, useful

class FloatingPoint(univ.OctetString):
    pass

class Unsigned(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, float('inf'))

class BCD(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, float('inf'))

class TimeOfDay(univ.OctetString):
    subtypeSpec = constraint.ConstraintsUnion(
        constraint.ValueSizeConstraint(4, 4),
        constraint.ValueSizeConstraint(6, 6)
    )

class MMSString(char.UTF8String):
    pass

class UtcTime(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(8, 8)

class Data(univ.Choice):
    pass

Data.componentType = namedtype.NamedTypes(
    namedtype.NamedType('array', univ.SequenceOf(componentType=Data()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('structure', univ.SequenceOf(componentType=Data()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
    namedtype.NamedType('boolean', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.NamedType('bit-string', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4))),
    namedtype.NamedType('integer', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
    namedtype.NamedType('unsigned', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6))),
    namedtype.NamedType('floating-point', FloatingPoint().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
    namedtype.NamedType('real', univ.Real().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8))),
    namedtype.NamedType('octet-string', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))),
    namedtype.NamedType('visible-string', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.NamedType('binary-time', TimeOfDay().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 12))),
    namedtype.NamedType('bcd', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 13))),
    namedtype.NamedType('booleanArray', univ.BitString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 14))),
    namedtype.NamedType('objId', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 15))),
    namedtype.NamedType('mMSString', MMSString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 16))),
    namedtype.NamedType('utc-time', UtcTime().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 17)))
)


class AllData(univ.SequenceOf):
    componentType = Data()


class IECGoosePDU(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'gocbRef',
            char.VisibleString().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType(
            'timeAllowedtoLive',
            univ.Integer().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
        namedtype.NamedType(
            'datSet',
            char.VisibleString().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
        namedtype.OptionalNamedType(
            'goID',
            char.VisibleString().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        ),
        namedtype.NamedType(
            't',
            UtcTime().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 4)
            )
        ),
        namedtype.NamedType(
            'stNum',
            univ.Integer().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 5)
            )
        ),
        namedtype.NamedType(
            'sqNum',
            univ.Integer().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 6)
            )
        ),
        namedtype.NamedType(
            'test',
            univ.Boolean(False).subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 7)
            )
        ),
        namedtype.NamedType(
            'confRev',
            univ.Integer().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 8)
            )
        ),
        namedtype.NamedType(
            'ndsCom',
            univ.Boolean(False).subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 9)
            )
        ),
        namedtype.NamedType(
            'numDatSetEntries',
            univ.Integer().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 10)
            )
        ),
        namedtype.NamedType(
            'allData',
            AllData().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 11)
            )
        ),
        namedtype.OptionalNamedType(
            'security',
            univ.OctetString().subtype(
                implicitTag=tag.Tag( tag.tagClassContext, tag.tagFormatSimple, 12)
            )
        ),
    )
