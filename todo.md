1. Check if copied keys are deleted always
   might want to create own class for keys 
   that "auto deletes" in finalize
   (it's not that bad idea in Python as refcounting 
   GC should clear memory fast enough.)
2. Add padding
3. If we need to keep up with the requirement of 
   "securely" storing keys we need to drop
   cryptorgraphy, as it insists of 
   getting everything as bytes. 
     
