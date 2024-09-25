import { CommonModule } from '@angular/common';
import { Component, computed, Input, signal, inject, output, Output, EventEmitter, effect } from '@angular/core';
import { MatButtonModule } from '@angular/material/button'
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { CropperDialoComponent, CropperDialoResult } from '../cropper-dialo/cropper-dialo.component';
import { filter } from 'rxjs';

@Component({
  selector: 'app-image-cont',
  standalone: true,
  imports: [CommonModule, MatButtonModule, MatDialogModule],
  templateUrl: './image-cont.component.html',
  styleUrl: './image-cont.component.scss'
})
export class ImageContComponent {

  imageWidth = signal(0);
  @Input() set width(val: number) {
    this.imageWidth.set(val);
  }

  imageheight = signal(0);
  @Input() set height(val: number) {
    this.imageheight.set(val);
  }

  placeholder = computed(() => `assets/ProfilePic.jpg`);
  
  croppedImage = signal<CropperDialoResult | undefined>(undefined)

  imageSource = computed( () => {

    if (this.croppedImage()) {
      return this.croppedImage()?.imageUrl;
    }
    return this.placeholder();
  
  })

  dialog = inject(MatDialog)

  fileSelected(event: any) {
    const file = event.target.files[0];
    if (file) {
      const dialogRef = this.dialog.open(CropperDialoComponent, {
        data: { image: file, width: this.imageWidth(), height: this.imageheight() },
        width: '500px'
      })

      dialogRef.afterClosed().pipe(filter(result => !!result)).subscribe((result) => {
        this.croppedImage.set(result);
      })
    }
  }

  @Output() imageReady = new EventEmitter<Blob>();
  
  constructor(){
    effect(() => {
      if(this.croppedImage()) {
        this.imageReady.emit(this.croppedImage()?.blob);
      }
    })
  }
}


