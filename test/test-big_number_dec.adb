with AUnit.Assertions; 
with Crypto.Types.Big_Numbers;
with Big_Number_Constants; 

pragma Elaborate_All(Crypto.Types.Big_Numbers);
pragma Optimize(Time);

package body Test.Big_Number_Dec is

------------------------------------------------------------------------------------
-------------------------------- Type - Declaration --------------------------------
------------------------------------------------------------------------------------

	package Big is new Crypto.Types.Big_Numbers(4096);
    use Big;
    use Big.Utils;
    
	use Big_Number_Constants;
	
	X_4096, X_3812, X_2048, X_1025, X_1024, X_768, X_582, X_1, X_0, P, Q, R, Z : 
	Big_Unsigned;

------------------------------------------------------------------------------------
------------------------------------ Constants -------------------------------------
------------------------------------------------------------------------------------

	procedure Constants is
	begin
	
		X_4096 := To_Big_Unsigned(Cons_4096);
		X_1025 := To_Big_Unsigned(Cons_1025);
		X_1024 := To_Big_Unsigned(Cons_1024);
		X_768  := To_Big_Unsigned(Cons_768);
		X_1 := To_Big_Unsigned("1");
		X_0 := To_Big_Unsigned("0");

	end Constants;

------------------------------------------------------------------------------------
---------------------------- Register Big_Number Test 1 ----------------------------
------------------------------------------------------------------------------------
	
	procedure Register_Tests(T : in out Big_Number_Test) is
		use Test_Cases.Registration;
	begin

		Register_Routine(T, Big_Number_Test1'Access,"Decrease with 4096 Bit");
		Register_Routine(T, Big_Number_Test2'Access,"Decrease with 1025 and 1024 Bit");
		Register_Routine(T, Big_Number_Test3'Access,"Decrease with 768 Bit");
		Register_Routine(T, Big_Number_Test4'Access,"Decrease with 1 and 0 Bit");

	end Register_Tests;

------------------------------------------------------------------------------------
------------------------------- Name Big Number Tests ------------------------------
------------------------------------------------------------------------------------

	function Name(T : Big_Number_Test) return Test_String is
	begin
		return new String'("Big Number Tests");
	end Name;

------------------------------------------------------------------------------------
------------------------------------ Start Tests -----------------------------------
------------------------------------------------------------------------------------
-------------------------------------- Test 1 --------------------------------------
------------------------------------------------------------------------------------

   procedure Big_Number_Test1(T : in out Test_Cases.Test_Case'Class) is
      use AUnit.Assertions; 
   begin
   	  
   	   Constants;
   	   Q := X_4096;
	   P := To_Big_Unsigned("10443888814131525066917527107166243825799642490473837" &
	   "80384233483283953907971557456848826811934997558340890106714439262837987573" &
	   "43818579360726323608785136527794595697654370999834036159013438371831442807" &
	   "00118559462263763188393977127456723346843445866174968079087058037040712840" &
	   "48740118609114467977783598029006686938976881787785946905630190260940599579" &
	   "45343282346930302669644305902501597239986771421554169383555988529148631823" &
	   "79144344967340878118726394964751001890413490084170616750936683338505510329" &
	   "72088269550769983616369411933015213796825837188091833656751221318492846368" &
	   "12555022599830041234478486259567449219461702380650591324561082573183538008" &
	   "76086221028342701976982023131690176780066751954850799216364193702853751247" &
	   "84014907159135459982790513399611551794271106831134090584272884279791554849" &
	   "78295432353451706522326906139490598769300212296339568778287894844061600741" &
	   "29456749198230505716423771548163213806310459029161369267083428564407304478" &
	   "99971901781465763473223850267253059899795996090799469201774624817718449867" &
	   "45565925017832907047311943316555080756822184657174637329688491281952031745" &
	   "70024409266169108741483850784119298045229818573389776481031260859030013024" &
	   "13467189726673216491511131602920781738033436090243804708340403154190334");
   	   Dec(Q); 
	   Assert(Q = P, "Failed.");
   
   end Big_Number_Test1;

------------------------------------------------------------------------------------
-------------------------------------- Test 2 --------------------------------------
------------------------------------------------------------------------------------

   procedure Big_Number_Test2(T : in out Test_Cases.Test_Case'Class) is
      use AUnit.Assertions; 
   begin

   	   Q := X_1025;
	   P := X_1024;
   	   Dec(Q); 
	   Assert(Q = P, "Failed.");

   end Big_Number_Test2;

------------------------------------------------------------------------------------
-------------------------------------- Test 3 --------------------------------------
------------------------------------------------------------------------------------

   procedure Big_Number_Test3(T : in out Test_Cases.Test_Case'Class) is
      use AUnit.Assertions; 
   begin
	   
   	   Q := X_768;
	   P := To_Big_Unsigned("10525180923007809127429104552568860171166966111390520" &
	   "38026050952686376886330878408828646477950487730697131073207283467158004411" &
	   "48023479283456794287275031281139204454972220848535026635469069847258252628" &
	   "9123371646877892846653816057849");
   	   Dec(Q); 
	   Assert(Q = P, "Failed.");

   end Big_Number_Test3;

------------------------------------------------------------------------------------
-------------------------------------- Test 4 --------------------------------------
------------------------------------------------------------------------------------

   procedure Big_Number_Test4(T : in out Test_Cases.Test_Case'Class) is
      use AUnit.Assertions; 
   begin

   	   Q := X_1;
   	   Dec(Q); 
	   Assert(Q = X_0, "Failed.");

   	   Q := X_0;
   	   Dec(Q); 
	   Assert(Q = X_4096, "Failed.");

   end Big_Number_Test4;

------------------------------------------------------------------------------------

end Test.Big_Number_Dec;
