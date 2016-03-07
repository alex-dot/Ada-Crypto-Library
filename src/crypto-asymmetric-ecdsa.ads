-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License as
-- published by the Free Software Foundation; either version 2 of the
-- License, or (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
-- 02111-1307, USA.

-- As a special exception, if other files instantiate generics from
-- this unit, or you link this unit with other files to produce an
-- executable, this unit does not by itself cause the resulting
-- executable to be covered by the GNU General Public License. This
-- exception does not however invalidate any other reasons why the
-- executable file might be covered by the GNU Public License.

with Crypto.Types; use Crypto.Types;
with Crypto.Types.Big_Numbers;
with Crypto.Types.Elliptic_Curves.Zp;
with Crypto.Types.Elliptic_Curves.Zp.Database;

generic
   Size : Positive;

package Crypto.Asymmetric.ECDSA is

   package Big is new Crypto.Types.Big_Numbers(Size);
   use Big;
   package EC  is new Crypto.Types.Elliptic_Curves(Big);
   use EC;
   package Zp is new EC.Zp;
   use Zp;
   package DB is new Zp.Database;
   use DB;


   type Public_Key_ECDSA is private;
   type Private_Key_ECDSA is private;
   type Signature_ECDSA is private;

--   subtype Serialized_PubKey     is Bytes(1..Public_Key_ECDSA'Size);
--   subtype Serialized_PrivKey    is Bytes(1..Private_Key_ECDSA'Size);
--   subtype Serialized_Sig        is Bytes(1..Signature_ECDSA'Size);
--   subtype Serialized_PubSig
--      is Bytes(1..(Public_Key_ECDSA'Size+Signature_ECDSA'Size));
--   subtype Serialized_PubPrivSig
--      is Bytes(1..(Public_Key_ECDSA'Size+Private_Key_ECDSA'Size+Signature_ECDSA'Size));

   subtype Serialized_PubKey     is Bytes(1..192);
   subtype Serialized_PrivKey    is Bytes(1..72);
   subtype Serialized_Sig        is Bytes(1..48);
   subtype Serialized_PubSig
      is Bytes(1..(Serialized_PubKey'Length+Serialized_Sig'Length));
   subtype Serialized_PubPrivSig
      is Bytes(1..(Serialized_PubKey'Length
                  +Serialized_PrivKey'Length
                  +Serialized_Sig'Length
                  -48)); -- we can save this because Q is already present in the PubKey

-------------------------------------------------------------------------------

   procedure Gen_Public_Key(
						Public_Key  : out Public_Key_ECDSA;
						length      : in DB.Bit_Length);

   procedure Gen_Private_Key(
						Public_Key  	: in out Public_Key_ECDSA;
                  Private_Key 	: out Private_Key_ECDSA);

   procedure Sign(
						Public_Key  : in Public_Key_ECDSA;
						Private_Key : in  Private_Key_ECDSA;
                  SHA1_Hash   : in  W_Block160;
                  Signature   : out Signature_ECDSA);

   function Verify(
						Public_Key  : Public_Key_ECDSA;
                  SHA1_Hash   : W_Block160;
                  Signature   : Signature_ECDSA) return Boolean;

-------------------------------------------------------------------------------

   procedure Sign_File(
						Filename    : in  String;
                 	Public_Key  : in Public_Key_ECDSA;
						Private_Key : in  Private_Key_ECDSA;
						Signature   : out Signature_ECDSA);

   function Verify_File(
						Filename   : String;
						Public_Key : Public_Key_ECDSA;
                  Signature  : Signature_ECDSA) return Boolean;

   function Verify_Key_Pair(
						Private_Key : Private_Key_ECDSA;
                  Public_Key  : Public_Key_ECDSA) return Boolean;

-------------------------------------------------------------------------------

	function equal_Public_Key_Curve(
 						Public_Key_A  : Public_Key_ECDSA;
						Public_Key_B  : Public_Key_ECDSA) return Boolean;

-------------------------------------------------------------------------------

   procedure Serialize_PubPrivSig
      ( Public_Key  : in     Public_Key_ECDSA;
        Private_Key : in     Private_Key_ECDSA;
        Signature   : in     Signature_ECDSA;
        Stream      :    out Serialized_PubPrivSig );

-------------------------------------------------------------------------------

   procedure Deserialize_PubPrivSig
      ( Stream      : in     Serialized_PubPrivSig;
        Public_Key  :    out Public_Key_ECDSA;
        Private_Key :    out Private_Key_ECDSA;
        Signature   :    out Signature_ECDSA );

-------------------------------------------------------------------------------

   procedure Serialize_PubSig
      ( Public_Key  : in     Public_Key_ECDSA;
        Signature   : in     Signature_ECDSA;
        Stream      :    out Serialized_PubSig );

-------------------------------------------------------------------------------

   procedure Deserialize_PubSig
      ( Stream      : in     Serialized_PubSig;
        Public_Key  :    out Public_Key_ECDSA;
        Signature   :    out Signature_ECDSA );

-------------------------------------------------------------------------------

   function Serialize_Public_key(
                  PK : in Public_Key_ECDSA) return Serialized_PubKey;

   function Serialize_Private_key(
                  PK : in Private_Key_ECDSA) return Serialized_PrivKey;

   function Serialize_Signature(
                  Sig : in Signature_ECDSA) return Serialized_Sig;

-------------------------------------------------------------------------------

   function Deserialize_Public_Key(
                  SPK : in Serialized_PubKey) return Public_Key_ECDSA;

   function Deserialize_Private_Key(
                  SPK : in Serialized_PrivKey) return Private_Key_ECDSA;

   function Deserialize_Signature(
                  SSig : in Serialized_Sig) return Signature_ECDSA;
   
   ---------------------------------------------------------------------------
   --------------------------------PRIVATE------------------------------------
   ---------------------------------------------------------------------------

private


   type ECDSA_P_KEY is record
      E : Elliptic_Curve_Zp;
      P : EC_Point; --x,y
      n : Big_Unsigned;
      Q : EC_Point; --x,y
   end record;

   type ECDSA_S_KEY is record
      Q : EC_Point; --x,y
      d : Big_Unsigned;
   end record;

   type ECDSA_KEY is record
      R : Big_Unsigned;
      S : Big_Unsigned;
   end record;

   type Public_Key_ECDSA is new ECDSA_P_KEY;
   type Private_Key_ECDSA is new ECDSA_S_KEY;
   type Signature_ECDSA is new ECDSA_KEY;

   pragma Optimize (Time);



end Crypto.Asymmetric.ECDSA;
