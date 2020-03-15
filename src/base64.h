//
//  base64.h
//  Socket Playground
//
//  Created by Tobias Zimmermann on 16.05.18.
//  Copyright © 2018 Tobias Zimmermann. All rights reserved.
//

#ifndef base64_h
#define base64_h

int b64_ntop(u_char const *src, size_t srclength, char *target, size_t targsize);
int b64_pton(char const *src, u_char *target, size_t targsize);

#endif /* base64_h */
