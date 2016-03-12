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

with Crypto.Symmetric.Hashfunction_SHA1; 

package body Crypto.Asymmetric.ECDSA is
   package SHA1 renames Crypto.Symmetric.Hashfunction_SHA1;
   use Big.Mod_Utils;
   use Big.Utils;



-------------------------------------------------------------------------------

   -- check if key is initialited
   function Is_Init(Key : ECDSA_P_KEY) return Boolean is
   begin
      if Key.n /= Big_Unsigned_Zero then
         return True;
      else return False;
      end if;
   end Is_Init; Pragma Inline (Is_Init);

-------------------------------------------------------------------------------

   -- check if key is initialited
   function Is_Init(Key : ECDSA_S_KEY) return Boolean is
   begin
      if Key.d /= Big_Unsigned_Zero then
			return True;
      else return False;
      end if;
   end Is_Init; Pragma Inline (Is_Init);

-------------------------------------------------------------------------------

   procedure Gen_Public_Key(
			    Public_Key  : out Public_Key_ECDSA;
			    length      : in DB.Bit_Length) is
   begin
      Get_Elliptic_Curve(Public_Key.E, Public_Key.P, Public_Key.n, length);
      init(Public_Key.E);
   end Gen_Public_Key;
   
   ----------------------------------------------------------------------------
   
   procedure Gen_Private_Key(
			     Public_Key  : in out Public_Key_ECDSA;
			     Private_Key : out Private_Key_ECDSA) is
   begin
      Private_Key.d := Get_Random(Get_P(Public_Key.E) - Big_Unsigned_Three)
	+ Big_Unsigned_One;
      
      Private_Key.Q 	:= Private_Key.d * Public_Key.P;
      Public_Key.Q 	:= Private_Key.Q;
   end Gen_Private_Key;
   
   ----------------------------------------------------------------------------

   procedure Sign(Public_Key  : in  Public_Key_ECDSA;
		  Private_Key : in  Private_Key_ECDSA;
                  SHA1_Hash   : in  W_Block160;
                  Signature   : out Signature_ECDSA) is
      temp_k : Big_Unsigned;
      temp_EC: EC_Point;
      temp_H : constant Big_Unsigned := To_Big_Unsigned(To_Bytes(Sha1_Hash));
   begin
      loop
	 temp_k := Get_Random(Get_P(Public_Key.E) - Big_Unsigned_Three) +
	   Big_Unsigned_One;
	 
	 temp_EC:= temp_k * Public_Key.P;
	 Signature.R := temp_EC.X mod Public_Key.n;
	 if Signature.R /= Big_Unsigned_Zero then
	    exit;
	 end if;
      end loop;
      
      Signature.S := Mult(Inverse(temp_k, Public_Key.n),
			  Add(temp_H, Mult(Private_Key.d, Signature.R, 
					   Public_Key.n),Public_Key.n),
			  Public_Key.n);
   end Sign;

-------------------------------------------------------------------------------
   
   function Verify(Public_Key  : Public_Key_ECDSA;
                   SHA1_Hash   : W_Block160;
                   Signature   : Signature_ECDSA) return Boolean is
      W  : constant Big_Unsigned := Inverse(Signature.S, Public_Key.n);
      U1 : constant Big_Unsigned := Mult(To_Big_Unsigned(To_Bytes(Sha1_Hash)),
					 W,Public_Key.n);
      U2 : constant Big_Unsigned := Mult(Signature.R, W, Public_Key.n);
      tmp_EC: constant EC_Point := (U1 * Public_Key.P) + (U2 * Public_Key.Q);
      V : constant Big_Unsigned:= tmp_EC.x mod Get_P(Public_Key.E);
   begin
      if V = Signature.R then return True;
      else return False;
      end if;
   end Verify;
   
-------------------------------------------------------------------------------

   procedure Sign_File(Filename    : in  String;
                       Public_Key  : in Public_Key_ECDSA;
		       Private_Key : in  Private_Key_ECDSA;
                       Signature   : out Signature_ECDSA) is
   begin
      if Is_Init(ECDSA_S_Key(Private_Key)) and 
	Is_Init(ECDSA_P_Key(Public_Key)) then
         Sign(Public_Key, Private_Key, SHA1.F_Hash(Filename), Signature);
      else
         raise Invalid_Private_Key_Error;
      end if;
   end Sign_File;

-------------------------------------------------------------------------------

   function Verify_File(
                        Filename   : String;
                        Public_Key : Public_Key_ECDSA;
                        Signature  : Signature_ECDSA) return Boolean is
   begin
      if Is_Init(ECDSA_P_Key(Public_Key)) then
         return Verify(Public_Key, SHA1.F_Hash(Filename), Signature);
      else
         raise Invalid_Public_Key_Error;
      end if;
   end Verify_File;


-------------------------------------------------------------------------------

   function Verify_Key_Pair(
                            Private_Key : Private_Key_ECDSA;
                            Public_Key  : Public_Key_ECDSA) return Boolean is
   begin
      if Is_Init(ECDSA_P_KEY(Public_Key)) = False or
        Is_Init(ECDSA_S_KEY(Private_Key)) = False then
         return False;
      elsif
			--- do some more? ---
        	(Private_Key.d * Public_Key.P = Public_Key.Q) and (Public_Key.Q = Private_Key.Q) then
         return True;
      else return False;
      end if;
   end Verify_Key_Pair;

-------------------------------------------------------------------------------

	function equal_Public_Key_Curve(
 						Public_Key_A  : Public_Key_ECDSA;
						Public_Key_B  : Public_Key_ECDSA) return Boolean is
	begin
		if (Public_Key_A.E = Public_Key_B.E) and (Public_Key_A.P = Public_Key_B.P) and (Public_Key_A.n = Public_Key_B.n) then
			return true;
		else
			return false;
		end if;
	end equal_Public_Key_Curve;

-------------------------------------------------------------------------------

   procedure Serialize_PubPrivSig
      ( Public_Key  : in     Public_Key_ECDSA;
        Private_Key : in     Private_Key_ECDSA;
        Signature   : in     Signature_ECDSA;
        Stream      :    out Serialized_PubPrivSig ) is
      Offset      : Natural := 1;
      Length      : Natural := 0;
   begin
      Length := Length + 8*Big.Big_Unsigned'Size/8;
      Stream(Offset..Length) := Serialize_Public_key(Public_Key);
      Offset := Length + 1;

      Offset := Offset - 2*Big.Big_Unsigned'Size/8; -- we save here
      Length := Length + 1*Big.Big_Unsigned'Size/8;
      Stream(Offset..Length) := Serialize_Private_key(Private_Key);
      Offset := Length + 1;

      Length := Length + 2*Big.Big_Unsigned'Size/8;
      Stream(Offset..Length) := Serialize_Signature(Signature);
   end Serialize_PubPrivSig;

-------------------------------------------------------------------------------

   procedure Deserialize_PubPrivSig
      ( Stream      : in     Serialized_PubPrivSig;
        Public_Key  :    out Public_Key_ECDSA;
        Private_Key :    out Private_Key_ECDSA;
        Signature   :    out Signature_ECDSA ) is
   begin
      Public_Key  := Deserialize_Public_Key(Stream(1..192));
      Private_Key := Deserialize_Private_Key(Stream(145..216));
      Signature   := Deserialize_Signature(Stream(217..264));
   end Deserialize_PubPrivSig;

-------------------------------------------------------------------------------

   procedure Serialize_PubSig
      ( Public_Key  : in     Public_Key_ECDSA;
        Signature   : in     Signature_ECDSA;
        Stream      :    out Serialized_PubSig ) is
   begin
      Stream(  1..192) := Serialize_Public_key(Public_Key);
      Stream(193..240) := Serialize_Signature(Signature);
   end Serialize_PubSig;

-------------------------------------------------------------------------------

   procedure Deserialize_PubSig
      ( Stream      : in     Serialized_PubSig;
        Public_Key  :    out Public_Key_ECDSA;
        Signature   :    out Signature_ECDSA ) is
   begin
      Public_Key := Deserialize_Public_Key(Stream(1..192));
      Signature  := Deserialize_Signature(Stream(193..240));
   end Deserialize_PubSig;

-------------------------------------------------------------------------------

   function Serialize_Public_key(
                  PK : in Public_Key_ECDSA) return Serialized_PubKey is
      SPK            : Serialized_PubKey;
      Offset         : Natural := 1;
      Length         : Natural := 0;
   begin

      Length := Length + Zp.Serialized_EC'Length;
      SPK(Offset..Length) := Zp.Serialize(PK.E);
      Offset := Length + 1;

      Length := Length + To_Bytes( PK.P.X )'Length;
      SPK(Offset..Length) := To_Bytes( PK.P.X );
      Offset := Length + 1;

      Length := Length + To_Bytes( PK.P.Y )'Length;
      SPK(Offset..Length) := To_Bytes( PK.P.Y );
      Offset := Length + 1;

      Length := Length + To_Bytes( PK.n )'Length;
      SPK(Offset..Length) := To_Bytes( PK.n );
      Offset := Length + 1;

      Length := Length + To_Bytes( PK.Q.X )'Length;
      SPK(Offset..Length) := To_Bytes( PK.Q.X );
      Offset := Length + 1;

      Length := Length + To_Bytes( PK.Q.Y )'Length;
      SPK(Offset..Length) := To_Bytes( PK.Q.Y );

      return SPK;
   end Serialize_Public_key;

   function Serialize_Private_key(
                  PK : in Private_Key_ECDSA) return Serialized_PrivKey is
      SPK            : Serialized_PrivKey;
      Offset         : Natural := 1;
      Length         : Natural := 0;
   begin

      Length := Length + To_Bytes( PK.Q.X )'Length;
      SPK(Offset..Length) := To_Bytes( PK.Q.X );
      Offset := Length + 1;

      Length := Length + To_Bytes( PK.Q.Y )'Length;
      SPK(Offset..Length) := To_Bytes( PK.Q.Y );
      Offset := Length + 1;

      Length := Length + To_Bytes( PK.d )'Length;
      SPK(Offset..Length) := To_Bytes( PK.d );

      return SPK;
   end Serialize_Private_key;

   function Serialize_Signature(
                  Sig : in Signature_ECDSA) return Serialized_Sig is
      SSig           : Serialized_Sig;
      Offset         : Natural := 1;
      Length         : Natural := 0;
   begin

      Length := Length + To_Bytes( Sig.R )'Length;
      SSig(Offset..Length) := To_Bytes( Sig.R );
      Offset := Length + 1;

      Length := Length + To_Bytes( Sig.S )'Length;
      SSig(Offset..Length) := To_Bytes( Sig.S );

      return SSig;
   end Serialize_Signature;

-------------------------------------------------------------------------------

   function Deserialize_Public_Key(
                  SPK : in Serialized_PubKey) return Public_Key_ECDSA is
      PK     : Public_Key_ECDSA;
      Offset : Natural := 1;
      Step   : constant Natural
         := To_Bytes( Big.Big_Unsigned_Last )'Length;
   begin
      PK.E    := Zp.Deserialize( SPK(Offset..3*Step) );
      Offset  := Offset + 3*Step;
      PK.P.X  := To_Big_Unsigned( SPK(Offset..Offset+Step-1) );
      Offset  := Offset + Step;
      PK.P.Y  := To_Big_Unsigned( SPK(Offset..Offset+Step-1) );
      Offset  := Offset + Step;
      PK.n    := To_Big_Unsigned( SPK(Offset..Offset+Step-1) );
      Offset  := Offset + Step;
      PK.Q.X  := To_Big_Unsigned( SPK(Offset..Offset+Step-1) );
      Offset  := Offset + Step;
      PK.Q.Y  := To_Big_Unsigned( SPK(Offset..Offset+Step-1) );
      return PK;
   end Deserialize_Public_Key;

   function Deserialize_Private_Key(
                  SPK : in Serialized_PrivKey) return Private_Key_ECDSA is
      PK : Private_Key_ECDSA;
   begin
      PK.Q.X := To_Big_Unsigned( SPK( 1..20) );
      PK.Q.Y := To_Big_Unsigned( SPK(21..40) );
      PK.d   := To_Big_Unsigned( SPK(41..60) );
      return PK;
   end Deserialize_Private_Key;

   function Deserialize_Signature(
                  SSig : in Serialized_Sig) return Signature_ECDSA is
      Sig : Signature_ECDSA;
   begin
      Sig.R := To_Big_Unsigned( SSig( 1..20) );
      Sig.S := To_Big_Unsigned( SSig(21..40) );
      return Sig;
   end Deserialize_Signature;

end Crypto.Asymmetric.ECDSA;
